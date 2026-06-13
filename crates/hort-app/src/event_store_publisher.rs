//! Thin wrapper around [`EventStore`] that broadcasts persisted events on
//! a [`tokio::sync::broadcast`] channel after a successful append.
//!
//! See `docs/architecture/explanation/event-notifications.md` (the
//! wrapper portion only). The [`NotificationDispatcher`]
//! subscribes to the broadcast sender; it is the only consumer.
//!
//! # Best-effort contract
//!
//! After a successful [`append`](EventStore::append), the publisher calls
//! [`broadcast::Sender::send`] for each persisted event. A [`broadcast::error::SendError`]
//! (no receivers, capacity exhausted) is silently dropped — the use-case
//! append path NEVER blocks on or retries broadcast.
//!
//! # No behaviour change without consumers
//!
//! When the broadcast sender is `None` (e.g. `HORT_NOTIFICATIONS_ENABLED=false`),
//! the publisher's [`append`](EventStore::append) is a transparent
//! pass-through to the inner event store — no extra allocation, no
//! `send` call. This keeps the publisher zero-cost for deployments that
//! don't enable notifications.

use std::sync::Arc;

use chrono::Utc;
use tokio::sync::broadcast;

use hort_domain::error::DomainResult;
use hort_domain::events::{PersistedEvent, StreamCategory, StreamId};
use hort_domain::ports::event_store::{
    AppendEvents, AppendResult, EventStore, ReadFrom, SubscribeFrom,
};
use hort_domain::ports::BoxFuture;

/// Application-layer wrapper around an [`EventStore`] that fans persisted
/// events out on a [`tokio::sync::broadcast::Sender`] after a successful
/// append.
///
/// Implements [`EventStore`] itself so call sites do not change shape —
/// only construction does. See module docs for the broadcast contract.
pub struct EventStorePublisher {
    inner: Arc<dyn EventStore>,
    /// `None` when notifications are disabled at composition root.
    sender: Option<broadcast::Sender<Arc<PersistedEvent>>>,
}

impl EventStorePublisher {
    /// Construct a publisher that broadcasts on every successful append.
    pub fn new(inner: Arc<dyn EventStore>, sender: broadcast::Sender<Arc<PersistedEvent>>) -> Self {
        Self {
            inner,
            sender: Some(sender),
        }
    }

    /// Construct a publisher with no broadcast channel — every append is
    /// a transparent pass-through. Used when `HORT_NOTIFICATIONS_ENABLED=false`
    /// and in tests / CLI binaries that do not run the dispatcher.
    pub fn without_broadcast(inner: Arc<dyn EventStore>) -> Self {
        Self {
            inner,
            sender: None,
        }
    }

    /// Subscribe to the broadcast channel.
    ///
    /// Returns `None` when the publisher was constructed without a sender
    /// (`HORT_NOTIFICATIONS_ENABLED=false`). Item 6b's dispatcher calls this
    /// once per process; other consumers (future projections, replicator)
    /// do likewise.
    pub fn subscribe(&self) -> Option<broadcast::Receiver<Arc<PersistedEvent>>> {
        self.sender.as_ref().map(broadcast::Sender::subscribe)
    }
}

/// Test helper: wrap an inner event store in a publisher with no
/// broadcast channel. Used by every use case's `#[cfg(test)]` block to
/// migrate `events.clone() as Arc<dyn EventStore>` → the new
/// `Arc<EventStorePublisher>` shape without churning surrounding code.
///
/// Available outside `hort-app` tests via the `test-support` feature so
/// the mock-context wiring in `hort-http-core::test_support` can use it.
#[cfg(any(test, feature = "test-support"))]
pub fn wrap_for_test<S: EventStore + 'static>(inner: Arc<S>) -> Arc<EventStorePublisher> {
    Arc::new(EventStorePublisher::without_broadcast(inner))
}

impl EventStore for EventStorePublisher {
    fn append(&self, batch: AppendEvents) -> BoxFuture<'_, DomainResult<AppendResult>> {
        // Fast-path when notifications are disabled: pure pass-through,
        // no clones, no broadcast.
        let Some(sender) = self.sender.clone() else {
            return self.inner.append(batch);
        };

        // Capture the inputs needed to reconstruct `PersistedEvent`s
        // post-append. The inner store assigns `stream_position` /
        // `global_positions`; everything else comes from the batch.
        // `event_version` is hardcoded at 1 — every shipped event is
        // version 1. If a future event version > 1 lands, this is a
        // known refactor pain point: thread the version through
        // `EventToAppend` or `AppendResult` instead of hardcoding here.
        // Conditional on `event_version > 1` shipping; no work until
        // then.
        let stream_id = batch.stream_id.clone();
        let actor = batch.actor.clone();
        let correlation_id = batch.correlation_id;
        let causation_id = batch.causation_id;
        let events_in = batch.events.clone();
        let inner = Arc::clone(&self.inner);

        Box::pin(async move {
            let result = inner.append(batch).await?;

            // Empty batches are technically permitted by the type
            // shape but are a no-op. Skip broadcast to avoid the
            // underflow on `stream_position - (n-1)`.
            let count = events_in.len();
            if count == 0 {
                return Ok(result);
            }

            // `stream_position` from the inner store is the position
            // of the LAST event in the batch. Earlier events live at
            // `last - (n-1) + i`. (See
            // `crates/hort-adapters-postgres/src/event_store.rs::append_with_conn`.)
            let stream_position_base = result.stream_position - (count as u64 - 1);
            for (i, eta) in events_in.iter().enumerate() {
                let persisted = PersistedEvent {
                    event_id: eta.event_id,
                    stream_id: stream_id.clone(),
                    stream_position: stream_position_base + i as u64,
                    global_position: result.global_positions[i],
                    event: eta.event.clone(),
                    correlation_id,
                    causation_id,
                    actor: actor.clone(),
                    // v1 invariant; see TODO above.
                    event_version: 1,
                    // The inner store assigns its own `stored_at` on
                    // the row. For broadcast purposes, "now" is
                    // acceptable — the broadcast is a hint, not the
                    // audit source. Consumers that need the
                    // authoritative `stored_at` re-read via
                    // `read_category`.
                    stored_at: Utc::now(),
                };
                // Silently drop SendError: best-effort by contract.
                // No receivers / lagged consumers are not the
                // publisher's concern; the use-case append path NEVER
                // blocks on broadcast outcome (design doc §11
                // invariant 1).
                let _ = sender.send(Arc::new(persisted));
            }

            Ok(result)
        })
    }

    fn read_stream(
        &self,
        stream_id: &StreamId,
        from: ReadFrom,
        max_count: u64,
    ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
        self.inner.read_stream(stream_id, from, max_count)
    }

    fn read_category(
        &self,
        category: StreamCategory,
        from: SubscribeFrom,
        max_count: u64,
    ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
        self.inner.read_category(category, from, max_count)
    }

    fn health_check(&self) -> BoxFuture<'_, DomainResult<()>> {
        self.inner.health_check()
    }

    fn delete_stream(&self, stream_id: StreamId) -> BoxFuture<'_, DomainResult<()>> {
        self.inner.delete_stream(stream_id)
    }

    fn archive_stream(&self, stream_id: StreamId, target: &str) -> BoxFuture<'_, DomainResult<()>> {
        self.inner.archive_stream(stream_id, target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use uuid::Uuid;

    use hort_domain::error::DomainError;
    use hort_domain::events::{system_actor, AuthenticationAttempted, DomainEvent};
    use hort_domain::ports::event_store::{EventToAppend, ExpectedVersion};

    // -- Inner mock specialised for these tests --
    //
    // Tests need (a) successful inner appends that return predictable
    // positions, and (b) a failing inner append. The use-case shared
    // `MockEventStore` always succeeds, so we use a local stub.

    enum InnerMockBehaviour {
        Success {
            stream_position_for_last: u64,
            global_positions: Vec<u64>,
        },
        Failure,
    }

    struct InnerMock {
        behaviour: InnerMockBehaviour,
        appends: Mutex<usize>,
    }

    impl InnerMock {
        fn success(stream_position_for_last: u64, global_positions: Vec<u64>) -> Self {
            Self {
                behaviour: InnerMockBehaviour::Success {
                    stream_position_for_last,
                    global_positions,
                },
                appends: Mutex::new(0),
            }
        }

        fn failure() -> Self {
            Self {
                behaviour: InnerMockBehaviour::Failure,
                appends: Mutex::new(0),
            }
        }

        fn append_count(&self) -> usize {
            *self.appends.lock().unwrap()
        }
    }

    impl EventStore for InnerMock {
        fn append(&self, _batch: AppendEvents) -> BoxFuture<'_, DomainResult<AppendResult>> {
            *self.appends.lock().unwrap() += 1;
            let behaviour = match &self.behaviour {
                InnerMockBehaviour::Success {
                    stream_position_for_last,
                    global_positions,
                } => Ok(AppendResult {
                    stream_position: *stream_position_for_last,
                    global_positions: global_positions.clone(),
                }),
                InnerMockBehaviour::Failure => {
                    Err(DomainError::Conflict("optimistic concurrency".into()))
                }
            };
            Box::pin(async move { behaviour })
        }

        fn read_stream(
            &self,
            _stream_id: &StreamId,
            _from: ReadFrom,
            _max_count: u64,
        ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn read_category(
            &self,
            _category: StreamCategory,
            _from: SubscribeFrom,
            _max_count: u64,
        ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn delete_stream(&self, _stream_id: StreamId) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }

        fn archive_stream(
            &self,
            _stream_id: StreamId,
            _target: &str,
        ) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    // -- Helpers --

    fn dummy_event() -> DomainEvent {
        DomainEvent::AuthenticationAttempted(AuthenticationAttempted {
            client_ip: "127.0.0.1".parse().unwrap(),
            result: "local_invalid_credentials".into(),
            external_id_if_decoded: None,
            at: Utc::now(),
        })
    }

    fn make_batch(events: Vec<EventToAppend>) -> AppendEvents {
        AppendEvents {
            stream_id: StreamId::auth_attempts(Utc::now().date_naive()),
            expected_version: ExpectedVersion::Any,
            events,
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: system_actor(),
        }
    }

    #[tokio::test]
    async fn publisher_without_broadcast_passes_through_append() {
        let inner = Arc::new(InnerMock::success(0, vec![100]));
        let publisher = EventStorePublisher::without_broadcast(inner.clone());

        let batch = make_batch(vec![EventToAppend::new(dummy_event())]);
        let result = publisher.append(batch).await.expect("append succeeds");

        assert_eq!(result.stream_position, 0);
        assert_eq!(result.global_positions, vec![100]);
        assert_eq!(inner.append_count(), 1);
        // No sender, no subscribe.
        assert!(publisher.subscribe().is_none());
    }

    #[tokio::test]
    async fn publisher_with_broadcast_fans_out_each_event() {
        let inner = Arc::new(InnerMock::success(
            /* stream_position of last (index 1) */ 6,
            vec![200, 201],
        ));
        let (sender, mut receiver) = broadcast::channel(16);
        let publisher = EventStorePublisher::new(inner, sender);

        let event0_id = Uuid::new_v4();
        let event1_id = Uuid::new_v4();
        let batch = make_batch(vec![
            EventToAppend {
                event_id: event0_id,
                event: dummy_event(),
            },
            EventToAppend {
                event_id: event1_id,
                event: dummy_event(),
            },
        ]);

        let result = publisher.append(batch).await.expect("append succeeds");
        assert_eq!(result.stream_position, 6);

        let first = receiver
            .recv()
            .await
            .expect("first broadcast event arrives");
        let second = receiver
            .recv()
            .await
            .expect("second broadcast event arrives");

        assert_eq!(first.event_id, event0_id);
        assert_eq!(first.stream_position, 5);
        assert_eq!(first.global_position, 200);
        assert_eq!(second.event_id, event1_id);
        assert_eq!(second.stream_position, 6);
        assert_eq!(second.global_position, 201);
    }

    #[tokio::test]
    async fn publisher_silently_drops_send_error_on_no_receivers() {
        let inner = Arc::new(InnerMock::success(1, vec![300, 301]));
        let (sender, _) = broadcast::channel::<Arc<PersistedEvent>>(1);
        let publisher = EventStorePublisher::new(inner.clone(), sender);

        // No receivers attached: every `send` returns SendError. The
        // publisher must swallow them and the append must still succeed.
        let batch = make_batch(vec![
            EventToAppend::new(dummy_event()),
            EventToAppend::new(dummy_event()),
        ]);

        let result = publisher.append(batch).await.expect("append succeeds");
        assert_eq!(result.stream_position, 1);
        assert_eq!(inner.append_count(), 1);
    }

    #[tokio::test]
    async fn publisher_does_not_broadcast_on_inner_error() {
        let inner = Arc::new(InnerMock::failure());
        let (sender, mut receiver) = broadcast::channel(16);
        let publisher = EventStorePublisher::new(inner.clone(), sender);

        let batch = make_batch(vec![EventToAppend::new(dummy_event())]);
        let err = publisher.append(batch).await.expect_err("append fails");
        assert!(matches!(err, DomainError::Conflict(_)));

        // No event should have been broadcast.
        let try_recv = receiver.try_recv();
        assert!(
            matches!(try_recv, Err(broadcast::error::TryRecvError::Empty)),
            "expected empty channel, got {try_recv:?}",
        );
        assert_eq!(inner.append_count(), 1);
    }

    #[tokio::test]
    async fn publisher_empty_batch_is_passthrough_no_broadcast() {
        let inner = Arc::new(InnerMock::success(0, vec![]));
        let (sender, mut receiver) = broadcast::channel(16);
        let publisher = EventStorePublisher::new(inner.clone(), sender);

        let batch = make_batch(Vec::new());
        let result = publisher.append(batch).await.expect("append succeeds");
        assert_eq!(result.stream_position, 0);
        assert_eq!(inner.append_count(), 1);
        let try_recv = receiver.try_recv();
        assert!(matches!(
            try_recv,
            Err(broadcast::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn publisher_is_dyn_event_store() {
        // Compile-time: resolves only if EventStorePublisher implements
        // EventStore in a dyn-compatible way.
        let inner: Arc<dyn EventStore> = Arc::new(InnerMock::success(0, vec![]));
        let publisher = EventStorePublisher::without_broadcast(inner);
        let _: &dyn EventStore = &publisher;
    }
}
