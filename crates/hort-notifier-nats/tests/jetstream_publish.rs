//! Integration tests for the NATS JetStream `EventNotifier` adapter.
//! Each test connects to an operator-supplied broker, creates the stream
//! it needs, and asserts the wire-level outcome.
//!
//! **Gating.** The suite is opt-in and needs a reachable broker: every
//! test early-returns unless `HORT_TEST_NATS=1` is set AND
//! `HORT_TEST_NATS_URL` names a JetStream-enabled server. No CI config
//! sets either variable, so the suite self-skips on every automated run
//! today — it is driven by hand against a broker the operator provides.
//! `nats:2.10` is the server floor matched by the `server_2_10` feature
//! the adapter selects.
//!
//! The broker wants to be a scratch one: a catch-all stream over
//! `events.>` would swallow the orphan subject and make the no-stream
//! assertion below unreachable.
//!
//! ```bash
//! HORT_TEST_NATS=1 HORT_TEST_NATS_URL=nats://127.0.0.1:4222 \
//!     cargo test -p hort-notifier-nats --test jetstream_publish
//! ```

#![allow(clippy::expect_used)]

use std::env;

use hort_domain::entities::subscription::{SubscriptionId, SubscriptionTarget};
use hort_domain::ports::event_notifier::{EventNotifier, NotifyFailureReason, NotifyOutcome};
use hort_notifier_nats::NatsNotifier;
use uuid::Uuid;

/// Sentinel env var. Mirrors the `DATABASE_URL` early-return pattern
/// used by the postgres adapter's integration suite.
fn nats_gate_enabled() -> bool {
    env::var("HORT_TEST_NATS").ok().as_deref() == Some("1")
}

/// The suite does not own a broker — it is handed one, so the endpoint is
/// the operator's to supply and has no default. Returns `None` with a
/// skip note naming the variable when the sentinel is on but no endpoint
/// is configured, so a bare `HORT_TEST_NATS=1` skips cleanly instead of
/// failing on a connection refused against a guessed address.
fn broker_url() -> Option<String> {
    match env::var("HORT_TEST_NATS_URL") {
        Ok(url) if !url.trim().is_empty() => Some(url),
        _ => {
            eprintln!(
                "SKIP jetstream_publish: HORT_TEST_NATS=1 but HORT_TEST_NATS_URL is unset or \
                 empty. Point the suite at a JetStream-enabled broker, e.g. \
                 HORT_TEST_NATS_URL=nats://127.0.0.1:4222."
            );
            None
        }
    }
}

/// Open an async-nats client + JetStream context against the given
/// broker URL, create a stream catching `subject`, and return both the
/// adapter under test and the raw JetStream context (so tests can poke at
/// stream state if needed).
///
/// Every test names its own stream and its own subject, so the two tests
/// below share one broker without interfering, and re-running them
/// against the same broker re-creates each stream with an identical
/// config rather than conflicting with the previous run's.
async fn setup_adapter_with_stream(
    url: &str,
    stream_name: &str,
    subject: &str,
) -> (NatsNotifier, async_nats::jetstream::Context) {
    let client = async_nats::connect(url)
        .await
        .expect("nats client connects");
    let js = async_nats::jetstream::new(client.clone());
    // Create a stream that catches the given subject. `subjects` is a
    // single-element vec because the adapter publishes to a literal
    // subject per `SubscriptionTarget::NatsJetStream::subject`.
    js.create_stream(async_nats::jetstream::stream::Config {
        name: stream_name.to_string(),
        subjects: vec![subject.to_string()],
        ..Default::default()
    })
    .await
    .expect("stream creates");
    let adapter = NatsNotifier::new(client);
    (adapter, js)
}

// ---------------------------------------------------------------------------
// Happy path — publish to a subject the broker catches and returns Delivered.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn publish_with_existing_stream_delivers() {
    if !nats_gate_enabled() {
        return;
    }
    let Some(url) = broker_url() else {
        return;
    };
    let subject = "events.artifact.ingested";
    let (adapter, _js) = setup_adapter_with_stream(&url, "EVENTS_INGESTED_DELIVER", subject).await;

    let target = SubscriptionTarget::NatsJetStream {
        subject: subject.to_string(),
    };
    let sub_id = SubscriptionId(Uuid::new_v4());
    let outcome = adapter.notify(&target, sub_id, &[]).await;
    assert_eq!(
        outcome,
        NotifyOutcome::Delivered,
        "happy-path publish + ack must return Delivered"
    );
}

// ---------------------------------------------------------------------------
// No-stream path — publishing to a subject no stream catches surfaces as
// `Failed { NatsNak }`, not as a transport failure. `classify_publish_error`
// maps `PublishErrorKind::StreamNotFound` into the permanent-NAK bucket
// because the condition does not heal: retrying the identical payload fails
// identically, so routing it to `ConnectionLost` would invite a retry that
// cannot succeed. The adapter's own unit tests pin that mapping.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn publish_to_subject_with_no_stream_returns_failed() {
    if !nats_gate_enabled() {
        return;
    }
    let Some(url) = broker_url() else {
        return;
    };
    // Create a stream that catches a DIFFERENT subject; publishing to
    // the orphan subject should fail the publish step (no_responders).
    let (adapter, _js) =
        setup_adapter_with_stream(&url, "EVENTS_NO_RESPONDERS", "events.unrelated.namespace").await;

    let target = SubscriptionTarget::NatsJetStream {
        subject: "events.orphan.subject".to_string(),
    };
    let sub_id = SubscriptionId(Uuid::new_v4());
    let outcome = adapter.notify(&target, sub_id, &[]).await;
    match outcome {
        NotifyOutcome::Failed {
            reason: NotifyFailureReason::NatsNak,
        } => {}
        other => panic!("expected Failed{{NatsNak}}, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Still uncovered, and not coverable from here: `NotifyOutcome::Failed`
// classification for a connection lost mid-publish and for a stalled ack.
// Both wanted; neither is expressible against a broker this suite does
// not own — one needs the broker process torn down at a chosen instant,
// the other needs an ack held back on demand, and a URL grants neither.
// The route is a deterministic TCP intercept or an in-process broker
// stub, not a container.
// ---------------------------------------------------------------------------
