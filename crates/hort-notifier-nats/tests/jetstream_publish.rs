//! Integration tests for the NATS JetStream `EventNotifier` adapter.
//! Each test stands up `nats:latest` with JetStream
//! enabled via `testcontainers`, asserts the wire-level outcome, and
//! drops the container at scope exit.
//!
//! **Gating.** All tests early-return when `HORT_TEST_NATS=1` is unset so
//! dev environments without Docker keep the suite green — same gating
//! discipline as `hort-adapters-postgres`'s `DATABASE_URL` tests. CI runs
//! this suite with the sentinel enabled.
//!
//! ```bash
//! HORT_TEST_NATS=1 cargo test -p hort-notifier-nats --test jetstream_publish
//! ```

#![allow(clippy::expect_used)]

use std::env;
use std::time::Duration;

use hort_domain::entities::subscription::{SubscriptionId, SubscriptionTarget};
use hort_domain::ports::event_notifier::{EventNotifier, NotifyFailureReason, NotifyOutcome};
use hort_notifier_nats::NatsNotifier;
use testcontainers::core::{ContainerPort, IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use uuid::Uuid;

/// NATS client port — the `nats` image exposes 4222 by default.
const NATS_PORT: u16 = 4222;

/// Container image and tag. `nats:2.10` is the floor matched by the
/// `server_2_10` feature flag the adapter selects.
const NATS_IMAGE: &str = "nats";
const NATS_TAG: &str = "2.10";

/// Sentinel env var. Mirrors the `DATABASE_URL` early-return pattern
/// used by the postgres adapter's integration suite.
fn nats_gate_enabled() -> bool {
    env::var("HORT_TEST_NATS").ok().as_deref() == Some("1")
}

/// Start a `nats:2.10` container with `-js` (JetStream enabled), wait
/// for the "Server is ready" log line, and return the live container
/// handle plus its host-mapped client port.
async fn start_nats() -> (ContainerAsync<GenericImage>, u16) {
    let container = GenericImage::new(NATS_IMAGE, NATS_TAG)
        .with_exposed_port(ContainerPort::Tcp(NATS_PORT))
        // The 2.10 image prints "Server is ready" once the listener
        // accepts client connections. Waiting for stdout avoids the
        // race where `connect` is attempted before the server binds.
        .with_wait_for(WaitFor::message_on_stderr("Server is ready"))
        .with_cmd(["-js"])
        .with_startup_timeout(Duration::from_secs(30))
        .start()
        .await
        .expect("nats container starts");
    let port = container
        .get_host_port_ipv4(NATS_PORT.tcp())
        .await
        .expect("nats container exposes host port");
    (container, port)
}

/// Open an async-nats client + JetStream context against the
/// container, create a stream catching `events.>`, and return both
/// the adapter under test and the raw JetStream context (so tests can
/// poke at stream state if needed).
async fn setup_adapter_with_stream(
    port: u16,
    stream_name: &str,
    subject: &str,
) -> (NatsNotifier, async_nats::jetstream::Context) {
    let url = format!("nats://127.0.0.1:{port}");
    let client = async_nats::connect(&url)
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
    let (_container, port) = start_nats().await;
    let subject = "events.artifact.ingested";
    let (adapter, _js) = setup_adapter_with_stream(port, "EVENTS_INGESTED_DELIVER", subject).await;

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
// No-stream path — publishing to a subject no stream catches surfaces
// as `Failed { ConnectionLost }` (the broad bucket for now; finer
// classification is future work per the adapter's module-level note).
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn publish_to_subject_with_no_stream_returns_failed() {
    if !nats_gate_enabled() {
        return;
    }
    let (_container, port) = start_nats().await;
    // Create a stream that catches a DIFFERENT subject; publishing to
    // the orphan subject should fail the publish step (no_responders).
    let (adapter, _js) =
        setup_adapter_with_stream(port, "EVENTS_NO_RESPONDERS", "events.unrelated.namespace").await;

    let target = SubscriptionTarget::NatsJetStream {
        subject: "events.orphan.subject".to_string(),
    };
    let sub_id = SubscriptionId(Uuid::new_v4());
    let outcome = adapter.notify(&target, sub_id, &[]).await;
    match outcome {
        NotifyOutcome::Failed {
            reason: NotifyFailureReason::ConnectionLost,
        } => {}
        other => panic!("expected Failed{{ConnectionLost}}, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Connection-lost path — kill the container mid-flight; the next
// publish surfaces as `Failed`. The dispatcher's failure budget
// handles the rest.
//
// Marked `#[ignore]` because:
//  - Container kill timing vs. async-nats internal reconnect is racy
//    on CI. Either we get `Failed { ConnectionLost }` on the first
//    publish after kill, or the client reconnect machinery surfaces
//    a different transient error. Both are valid for the design-doc
//    contract (no retry, surface failure) but the test as written
//    is too narrow to be reliable.
//  - The happy-path test above already exercises the same publish
//    code path under a live broker; this test would add coverage
//    only of the very narrow window between disconnect and the next
//    publish attempt.
//
// Future work: replace with a fixture that intercepts the TCP
// stream and tears it down deterministically (e.g. via a proxy).
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
#[ignore = "TODO(test-infra): container-kill timing is racy; needs deterministic TCP intercept"]
async fn connection_lost_during_publish_returns_failed() {
    if !nats_gate_enabled() {
        return;
    }
    let (container, port) = start_nats().await;
    let subject = "events.artifact.kill_test";
    let (adapter, _js) = setup_adapter_with_stream(port, "EVENTS_KILL", subject).await;

    let target = SubscriptionTarget::NatsJetStream {
        subject: subject.to_string(),
    };
    let sub_id = SubscriptionId(Uuid::new_v4());
    // First publish — must succeed against the live broker.
    let first = adapter.notify(&target, sub_id, &[]).await;
    assert_eq!(first, NotifyOutcome::Delivered);

    // Stop the broker, then attempt a second publish.
    container.stop().await.expect("stop container");
    // Give the kernel a moment to reset the TCP connection state.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let outcome = adapter.notify(&target, sub_id, &[]).await;
    match outcome {
        NotifyOutcome::Failed { .. } => {}
        other => panic!("expected Failed{{..}}, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Ack-timeout path — forcing an ack timeout against a real broker is
// inherently flaky (the broker either acks within ms or returns an
// error; there is no public knob to delay ack synthetically). Marked
// `#[ignore]` for the same reason as the kill test.
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
#[ignore = "TODO(test-infra): no deterministic way to stall an ack against a real broker"]
async fn ack_timeout_classified_correctly() {
    if !nats_gate_enabled() {
        return;
    }
    // Placeholder body — if a future fixture introduces a way to
    // synthetically delay JetStream acks (e.g. a custom dummy NATS
    // server), wire the assertion through this test. The adapter
    // contract under test: `NotifyOutcome::Failed { reason:
    // NotifyFailureReason::AckTimeout }` after 2s.
    let _ = NotifyFailureReason::AckTimeout;
}
