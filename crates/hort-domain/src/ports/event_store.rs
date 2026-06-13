use uuid::Uuid;

use crate::error::DomainResult;
use crate::events::{Actor, DomainEvent, PersistedEvent, StreamCategory, StreamId};

use super::BoxFuture;

// ---------------------------------------------------------------------------
// ExpectedVersion
// ---------------------------------------------------------------------------

/// Expected version for optimistic concurrency on append.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedVersion {
    /// The stream must not exist. First write creates it.
    NoStream,
    /// The stream must be at exactly this position.
    Exact(u64),
    /// No concurrency check — append regardless of current position.
    Any,
}

// ---------------------------------------------------------------------------
// AppendEvents
// ---------------------------------------------------------------------------

/// An event plus its persisted identity.
///
/// `event_id` is caller-supplied (not adapter-generated). Use cases that
/// emit an event AND need to reference its id as `causation_id` on a
/// later event mint the id with `Uuid::new_v4()` before calling
/// [`EventStore::append`] / `ArtifactLifecyclePort::commit_transition` /
/// `RefLifecyclePort::move_ref` / `ArtifactGroupLifecyclePort::commit_member_added`
/// / etc. The adapter binds `event_id` verbatim — "adapter is pure
/// persistence" extends from payload to identity (ADR 0004).
#[derive(Debug, Clone, PartialEq)]
pub struct EventToAppend {
    pub event_id: Uuid,
    pub event: DomainEvent,
}

impl EventToAppend {
    /// Convenience constructor that mints a fresh `event_id`. Use this
    /// when the caller has no downstream causation reference to thread.
    pub fn new(event: DomainEvent) -> Self {
        Self {
            event_id: Uuid::new_v4(),
            event,
        }
    }
}

/// A batch of events to append, sharing correlation and actor context.
///
/// **Security note:** `correlation_id` is always generated server-side by the
/// use case (via `Uuid::new_v4()`), never accepted from client input. This
/// prevents correlation ID collisions that could pollute audit trails.
/// If an API client needs idempotency, it supplies a separate idempotency key
/// that the handler validates independently.
#[derive(Debug, Clone)]
pub struct AppendEvents {
    pub stream_id: StreamId,
    pub expected_version: ExpectedVersion,
    /// Caller-supplied events with caller-supplied `event_id`s. The
    /// adapter binds `event_id` verbatim — it never mints.
    pub events: Vec<EventToAppend>,
    /// Always server-generated via `Uuid::new_v4()`, never from client input.
    pub correlation_id: Uuid,
    /// The event that caused this batch (if reacting to another event).
    pub causation_id: Option<Uuid>,
    pub actor: Actor,
}

// ---------------------------------------------------------------------------
// AppendResult
// ---------------------------------------------------------------------------

/// The result of a successful append.
#[derive(Debug, Clone, PartialEq)]
pub struct AppendResult {
    /// The new stream position after the last appended event.
    pub stream_position: u64,
    /// The global positions assigned to the appended events.
    pub global_positions: Vec<u64>,
}

// ---------------------------------------------------------------------------
// ReadFrom / SubscribeFrom
// ---------------------------------------------------------------------------

/// Position to read from in a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadFrom {
    /// Start from the beginning of the stream.
    Start,
    /// Start after the given stream position (exclusive).
    After(u64),
}

/// Position to subscribe from across all streams (global ordering).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscribeFrom {
    /// Start from the beginning of the global log.
    Start,
    /// Start after the given global position (exclusive).
    AfterGlobal(u64),
}

// ---------------------------------------------------------------------------
// EventStore trait
// ---------------------------------------------------------------------------

/// Backend-agnostic event store port.
///
/// Supports both PostgreSQL append-only tables and native event stores.
/// All operations are expressed in domain terms — streams, events, versions.
///
/// **Hard constraint:** this trait must not contain PostgreSQL-isms (e.g.
/// `PgPool`, `LISTEN/NOTIFY` channel names, `sqlx` types). An EventStoreDB
/// adapter must be implementable against this trait without changes.
pub trait EventStore: Send + Sync {
    /// Append events to a stream with optimistic concurrency.
    ///
    /// Returns `DomainError::Conflict` if the expected version does not match
    /// the current stream position.
    fn append(&self, batch: AppendEvents) -> BoxFuture<'_, DomainResult<AppendResult>>;

    /// Read events from a stream, starting at the given position.
    ///
    /// Returns events in stream-position order. Returns an empty vec if the
    /// stream does not exist or `from` is past the end.
    fn read_stream(
        &self,
        stream_id: &StreamId,
        from: ReadFrom,
        max_count: u64,
    ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>>;

    /// Read events from all streams in a category, ordered by global position.
    ///
    /// Used by projections that consume all events of a given aggregate type
    /// (e.g. all `artifact-*` streams for the quarantine status projection).
    fn read_category(
        &self,
        category: StreamCategory,
        from: SubscribeFrom,
        max_count: u64,
    ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>>;

    /// Lightweight liveness probe — `Ok(())` if the underlying store
    /// can serve a trivial round-trip, `Err(_)` otherwise.
    ///
    /// Wired into the `/readyz` HTTP probe on
    /// the public listener so kubelet readinessProbe can detect a
    /// dropped DB connection / unreachable event store. The Postgres
    /// adapter implements this as a `SELECT 1` round-trip on its
    /// `PgPool`, which inherently exercises pool acquisition + DB
    /// responsiveness in one call (the same pool backs every other
    /// `EventStore` operation, so a successful ping means the entire
    /// event-store path is healthy).
    ///
    /// Default impl returns `Ok(())` so existing in-memory mock
    /// implementations remain compatible without churn — they have no
    /// I/O to fail. Production adapters override.
    fn health_check(&self) -> BoxFuture<'_, DomainResult<()>> {
        Box::pin(async { Ok(()) })
    }

    /// Delete an entire stream.
    ///
    /// **Caller preconditions** (NOT enforced by the adapter — the
    /// eventstore-retention use case is responsible for proving them
    /// before calling):
    /// 1. The stream's last event is a terminal event for its category
    ///    (`ArtifactPurged` for artifact streams, equivalent terminals
    ///    for other categories — see
    ///    `crate::ports::terminal_stream_reader`).
    /// 2. The audit-retention floor has elapsed for
    ///    every event in the stream.
    ///
    /// Implementations MAY refuse if the stream is still subscribed to
    /// by an active projection.
    ///
    /// The Postgres adapter implements this as a seal-and-remove
    /// (single-flight via the seal pool, ADR 0020); in-memory mocks
    /// implement whatever their test needs.
    fn delete_stream(&self, stream_id: StreamId) -> BoxFuture<'_, DomainResult<()>>;

    /// Move an entire stream to a cold-storage target.
    ///
    /// Same caller preconditions as [`Self::delete_stream`]. The `target`
    /// string is adapter-defined: e.g. `s3://archive-bucket/<prefix>`
    /// for the Postgres adapter, a separate stream category for an
    /// EventStoreDB / KurrentDB adapter. The trait deliberately does
    /// not encode a structured target type — the cold-storage backend
    /// choice is deliberately open.
    ///
    /// Implementation posture mirrors
    /// [`Self::delete_stream`].
    fn archive_stream(&self, stream_id: StreamId, target: &str) -> BoxFuture<'_, DomainResult<()>>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Dyn-compatibility compile-time assertion --

    /// This function is never called. Its existence forces the compiler to
    /// verify that `EventStore` is dyn-compatible. If someone later adds a
    /// method with `-> impl Trait` or generic parameters, this will fail.
    #[test]
    fn port_is_dyn_compatible() {
        // Compile-time: resolves only if the trait is dyn-compatible.
        // Runtime: size_of call executes in the test body for coverage.
        let _ = size_of::<&dyn EventStore>();
    }

    // -- ExpectedVersion --

    #[test]
    fn expected_version_no_stream_eq() {
        assert_eq!(ExpectedVersion::NoStream, ExpectedVersion::NoStream);
    }

    #[test]
    fn expected_version_exact_eq() {
        assert_eq!(ExpectedVersion::Exact(5), ExpectedVersion::Exact(5));
    }

    #[test]
    fn expected_version_exact_ne() {
        assert_ne!(ExpectedVersion::Exact(5), ExpectedVersion::Exact(6));
    }

    #[test]
    fn expected_version_any_eq() {
        assert_eq!(ExpectedVersion::Any, ExpectedVersion::Any);
    }

    #[test]
    fn expected_version_cross_variant_ne() {
        assert_ne!(ExpectedVersion::NoStream, ExpectedVersion::Any);
        assert_ne!(ExpectedVersion::NoStream, ExpectedVersion::Exact(0));
    }

    #[test]
    fn expected_version_clone_copy() {
        let v = ExpectedVersion::Exact(42);
        let copied = v; // Copy
        #[allow(clippy::clone_on_copy)]
        let cloned = v.clone(); // Intentionally test Clone impl
        assert_eq!(v, copied);
        assert_eq!(v, cloned);
    }

    // -- ReadFrom --

    #[test]
    fn read_from_start_eq() {
        assert_eq!(ReadFrom::Start, ReadFrom::Start);
    }

    #[test]
    fn read_from_after_eq() {
        assert_eq!(ReadFrom::After(3), ReadFrom::After(3));
    }

    #[test]
    fn read_from_after_ne() {
        assert_ne!(ReadFrom::After(3), ReadFrom::After(4));
    }

    #[test]
    fn read_from_cross_variant_ne() {
        assert_ne!(ReadFrom::Start, ReadFrom::After(0));
    }

    #[test]
    fn read_from_clone_copy() {
        let r = ReadFrom::After(10);
        let copied = r; // Copy
        #[allow(clippy::clone_on_copy)]
        let cloned = r.clone(); // Intentionally test Clone impl
        assert_eq!(r, copied);
        assert_eq!(r, cloned);
    }

    // -- SubscribeFrom --

    #[test]
    fn subscribe_from_start_eq() {
        assert_eq!(SubscribeFrom::Start, SubscribeFrom::Start);
    }

    #[test]
    fn subscribe_from_after_global_eq() {
        assert_eq!(
            SubscribeFrom::AfterGlobal(10),
            SubscribeFrom::AfterGlobal(10)
        );
    }

    #[test]
    fn subscribe_from_after_global_ne() {
        assert_ne!(
            SubscribeFrom::AfterGlobal(10),
            SubscribeFrom::AfterGlobal(11)
        );
    }

    #[test]
    fn subscribe_from_cross_variant_ne() {
        assert_ne!(SubscribeFrom::Start, SubscribeFrom::AfterGlobal(0));
    }

    #[test]
    fn subscribe_from_clone_copy() {
        let s = SubscribeFrom::AfterGlobal(99);
        let copied = s; // Copy
        #[allow(clippy::clone_on_copy)]
        let cloned = s.clone(); // Intentionally test Clone impl
        assert_eq!(s, copied);
        assert_eq!(s, cloned);
    }

    // -- AppendResult --

    #[test]
    fn append_result_construction_and_eq() {
        let r1 = AppendResult {
            stream_position: 3,
            global_positions: vec![100, 101, 102],
        };
        let r2 = AppendResult {
            stream_position: 3,
            global_positions: vec![100, 101, 102],
        };
        assert_eq!(r1, r2);
    }

    #[test]
    fn append_result_ne() {
        let r1 = AppendResult {
            stream_position: 3,
            global_positions: vec![100],
        };
        let r2 = AppendResult {
            stream_position: 4,
            global_positions: vec![100],
        };
        assert_ne!(r1, r2);
    }

    #[test]
    fn append_result_clone() {
        let r = AppendResult {
            stream_position: 1,
            global_positions: vec![50],
        };
        let cloned = r.clone();
        assert_eq!(r, cloned);
    }

    // -- AppendEvents construction --

    #[test]
    fn append_events_construction() {
        use crate::events::{ApiActor, ArtifactIngested, IngestSource};
        use crate::types::ContentHash;

        let hash: ContentHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .unwrap();
        let artifact_id = Uuid::new_v4();
        let batch = AppendEvents {
            stream_id: StreamId::artifact(artifact_id),
            expected_version: ExpectedVersion::NoStream,
            events: vec![EventToAppend::new(DomainEvent::ArtifactIngested(
                ArtifactIngested {
                    artifact_id,
                    repository_id: Uuid::new_v4(),
                    name: "test-pkg".into(),
                    version: Some("1.0.0".into()),
                    sha256: hash,
                    size_bytes: 512,
                    source: IngestSource::Direct,
                    metadata: serde_json::Value::Null,
                    metadata_blob: None,
                    upstream_published_at: None,
                },
            ))],
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: Actor::Api(ApiActor {
                user_id: Uuid::new_v4(),
            }),
        };

        assert_eq!(batch.stream_id.category, StreamCategory::Artifact);
        assert_eq!(batch.expected_version, ExpectedVersion::NoStream);
        assert_eq!(batch.events.len(), 1);
        assert!(batch.causation_id.is_none());
    }
}
