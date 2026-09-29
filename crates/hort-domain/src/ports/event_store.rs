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

    /// Read events from every stream in **any** of `categories` as ONE
    /// `global_position`-ordered page.
    ///
    /// The result is the first `max_count` events of the merged stream
    /// above `from` — not a concatenation of per-category pages. That is
    /// the difference that matters to a caller holding a cursor: a
    /// consumer of several categories can track **one** position over
    /// **one** ordered stream, and a position it has passed is a position
    /// it has read in every category. Walking the categories separately
    /// and checkpointing a single scalar cannot say that — an advance
    /// driven by one category steps the mark over another category's
    /// unread events, which is silent, unrecoverable loss.
    ///
    /// A page shorter than `max_count` means every category is at its
    /// head. Duplicate entries in `categories` are read once. An empty
    /// `categories` yields an empty page without touching the store.
    ///
    /// The default implementation merges [`Self::read_category`] calls —
    /// correct for every backend, and the right answer for the in-memory
    /// doubles that make up most implementations of this trait (same
    /// rationale as [`Self::health_check`]'s default). It costs one round
    /// trip per category and fetches up to `categories.len() * max_count`
    /// events to return `max_count`, so a backend that can express the
    /// merge in one query should override it; the Postgres adapter does.
    fn read_categories<'a>(
        &'a self,
        categories: &[StreamCategory],
        from: SubscribeFrom,
        max_count: u64,
    ) -> BoxFuture<'a, DomainResult<Vec<PersistedEvent>>> {
        let mut wanted: Vec<StreamCategory> = Vec::with_capacity(categories.len());
        for &cat in categories {
            if !wanted.contains(&cat) {
                wanted.push(cat);
            }
        }
        Box::pin(async move {
            let mut merged: Vec<PersistedEvent> = Vec::new();
            for cat in wanted {
                merged.extend(self.read_category(cat, from, max_count).await?);
            }
            // Truncating the sorted union to `max_count` yields exactly
            // the merged stream's first `max_count` events: the k-th
            // smallest overall (k <= max_count) is at most the k-th
            // smallest of its own category, so it is inside that
            // category's page.
            merged.sort_by_key(|e| e.global_position);
            merged.truncate(max_count as usize);
            Ok(merged)
        })
    }

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

    // -- read_categories default-implementation double ------------------
    //
    // A minimal `EventStore` that serves a per-category feed and records
    // which categories were asked for, so the default merge can be
    // pinned without an adapter.

    use std::collections::HashMap;
    use std::sync::Mutex;

    struct FeedStore {
        feeds: HashMap<StreamCategory, Vec<u64>>,
        asked: Mutex<Vec<StreamCategory>>,
        fail_on: Option<StreamCategory>,
    }

    impl FeedStore {
        fn new(feeds: &[(StreamCategory, &[u64])]) -> Self {
            Self {
                feeds: feeds
                    .iter()
                    .map(|(cat, positions)| (*cat, positions.to_vec()))
                    .collect(),
                asked: Mutex::new(Vec::new()),
                fail_on: None,
            }
        }

        fn failing(cat: StreamCategory) -> Self {
            let mut s = Self::new(&[(cat, &[1])]);
            s.fail_on = Some(cat);
            s
        }
    }

    /// The double serves category reads and nothing else; everything
    /// outside that surface answers with this rather than panicking, so
    /// a future test that reaches for one gets a message instead of an
    /// abort (and so the arms stay covered — this crate's coverage floor
    /// is 100%).
    fn out_of_scope() -> crate::error::DomainError {
        crate::error::DomainError::Invariant(
            "the read_categories double implements the category-read path only".into(),
        )
    }

    impl EventStore for FeedStore {
        fn append(&self, _batch: AppendEvents) -> BoxFuture<'_, DomainResult<AppendResult>> {
            Box::pin(async { Err(out_of_scope()) })
        }

        fn read_stream(
            &self,
            _stream_id: &StreamId,
            _from: ReadFrom,
            _max_count: u64,
        ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
            Box::pin(async { Err(out_of_scope()) })
        }

        fn read_category(
            &self,
            category: StreamCategory,
            from: SubscribeFrom,
            max_count: u64,
        ) -> BoxFuture<'_, DomainResult<Vec<PersistedEvent>>> {
            self.asked.lock().unwrap().push(category);
            if self.fail_on == Some(category) {
                return Box::pin(async {
                    Err(crate::error::DomainError::Invariant("read failed".into()))
                });
            }
            let after = match from {
                SubscribeFrom::Start => 0,
                SubscribeFrom::AfterGlobal(n) => n,
            };
            let events: Vec<PersistedEvent> = self
                .feeds
                .get(&category)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|p| *p > after)
                .take(max_count as usize)
                .map(|p| test_event(category, p))
                .collect();
            Box::pin(async move { Ok(events) })
        }

        fn delete_stream(&self, _stream_id: StreamId) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Err(out_of_scope()) })
        }

        fn archive_stream(
            &self,
            _stream_id: StreamId,
            _target: &str,
        ) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Err(out_of_scope()) })
        }
    }

    fn test_event(category: StreamCategory, global_position: u64) -> PersistedEvent {
        use crate::events::{system_actor, AuthenticationAttempted, DomainEvent};
        PersistedEvent {
            event_id: Uuid::new_v4(),
            stream_id: StreamId {
                category,
                entity_id: Uuid::nil(),
            },
            stream_position: 0,
            global_position,
            event: DomainEvent::AuthenticationAttempted(AuthenticationAttempted {
                client_ip: std::net::IpAddr::from([127, 0, 0, 1]),
                result: "local_invalid_credentials".to_string(),
                external_id_if_decoded: None,
                at: chrono::Utc::now(),
            }),
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: system_actor(),
            event_version: 1,
            stored_at: chrono::Utc::now(),
        }
    }

    fn positions(events: &[PersistedEvent]) -> Vec<u64> {
        events.iter().map(|e| e.global_position).collect()
    }

    #[tokio::test]
    async fn read_categories_returns_one_globally_ordered_page() {
        let store = FeedStore::new(&[
            (StreamCategory::Artifact, &[11, 13]),
            (StreamCategory::Ref, &[10, 12]),
        ]);
        let page = store
            .read_categories(
                &[StreamCategory::Artifact, StreamCategory::Ref],
                SubscribeFrom::Start,
                10,
            )
            .await
            .expect("read succeeds");
        assert_eq!(
            positions(&page),
            vec![10, 11, 12, 13],
            "the merge is by global position, not by the order the categories were listed"
        );
    }

    #[tokio::test]
    async fn read_categories_truncates_to_the_merged_streams_first_page() {
        let store = FeedStore::new(&[
            (StreamCategory::Artifact, &[3, 5, 7]),
            (StreamCategory::Ref, &[1, 2, 9]),
        ]);
        let page = store
            .read_categories(
                &[StreamCategory::Artifact, StreamCategory::Ref],
                SubscribeFrom::Start,
                3,
            )
            .await
            .expect("read succeeds");
        assert_eq!(positions(&page), vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn read_categories_honours_the_from_position() {
        let store = FeedStore::new(&[
            (StreamCategory::Artifact, &[1, 4]),
            (StreamCategory::Ref, &[2, 5]),
        ]);
        let page = store
            .read_categories(
                &[StreamCategory::Artifact, StreamCategory::Ref],
                SubscribeFrom::AfterGlobal(2),
                10,
            )
            .await
            .expect("read succeeds");
        assert_eq!(positions(&page), vec![4, 5]);
    }

    #[tokio::test]
    async fn read_categories_reads_a_repeated_category_once() {
        let store = FeedStore::new(&[(StreamCategory::Artifact, &[1, 2])]);
        let page = store
            .read_categories(
                &[
                    StreamCategory::Artifact,
                    StreamCategory::Artifact,
                    StreamCategory::Artifact,
                ],
                SubscribeFrom::Start,
                10,
            )
            .await
            .expect("read succeeds");
        assert_eq!(positions(&page), vec![1, 2], "no duplicated events");
        assert_eq!(store.asked.lock().unwrap().len(), 1, "no duplicated reads");
    }

    #[tokio::test]
    async fn read_categories_with_no_categories_does_not_touch_the_store() {
        let store = FeedStore::new(&[(StreamCategory::Artifact, &[1])]);
        let page = store
            .read_categories(&[], SubscribeFrom::Start, 10)
            .await
            .expect("read succeeds");
        assert!(page.is_empty());
        assert!(store.asked.lock().unwrap().is_empty());
    }

    /// Keeps the double's out-of-scope arms exercised rather than dead:
    /// this crate's coverage floor is 100%, and an `unimplemented!()` body
    /// nothing calls is an uncovered line.
    #[tokio::test]
    async fn the_double_serves_category_reads_and_nothing_else() {
        let store = FeedStore::new(&[(StreamCategory::Artifact, &[1])]);
        let batch = AppendEvents {
            stream_id: StreamId::artifact(Uuid::new_v4()),
            expected_version: ExpectedVersion::Any,
            events: Vec::new(),
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: crate::events::system_actor(),
        };
        assert!(store.append(batch).await.is_err());
        assert!(store
            .read_stream(&StreamId::artifact(Uuid::nil()), ReadFrom::Start, 1)
            .await
            .is_err());
        assert!(store
            .delete_stream(StreamId::artifact(Uuid::nil()))
            .await
            .is_err());
        assert!(store
            .archive_stream(StreamId::artifact(Uuid::nil()), "s3://nowhere")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn read_categories_propagates_a_read_failure() {
        let store = FeedStore::failing(StreamCategory::Artifact);
        let err = store
            .read_categories(&[StreamCategory::Artifact], SubscribeFrom::Start, 10)
            .await
            .expect_err("the failure must not be swallowed");
        assert!(matches!(err, crate::error::DomainError::Invariant(_)));
    }

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
