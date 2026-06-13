//! `MeteredEphemeralStore` — wrapper that forwards every call to an
//! inner [`EphemeralStore`] and emits the `hort_ephemeral_store_*`
//! metric pair on every operation.
//!
//! Metric catalog (`docs/metrics-catalog.md`):
//!
//! - `hort_ephemeral_store_operations_total{operation, result, class}` —
//!   counter; incremented once per call.
//! - `hort_ephemeral_store_operation_duration_seconds{operation, class}` —
//!   histogram; records elapsed wall-clock.
//!
//! `operation` ∈ {`get`, `put`, `put_if_absent`, `compare_and_swap`,
//! `delete`, `extend_ttl`, `try_increment_counter`}.
//! `result` ∈ {`ok`, `cas_miss`, `not_found`, `error`}.
//! `class` ∈ {`evictable`, `durable`} — ephemeral-store routing class
//! (see `docs/metrics-catalog.md`). All label values are static strings
//! so the metrics crate's labelset pooling stays cheap.
//!
//! # `#[tracing::instrument]` shape
//!
//! The port trait uses the workspace's `BoxFuture<'_, T>` alias with
//! multi-input elision (`&self` + `&str`). `#[instrument]` cannot
//! be placed directly on a non-async function that returns a
//! `BoxFuture<'_, …>` in this shape — the macro's expansion
//! conflicts with the lifetime inference. We therefore put the
//! `#[instrument]` attribute on a separate `async fn` helper per
//! operation, then `Box::pin` the call inside the trait method.
//! This matches the non-negotiable constraint ("`#[tracing::instrument(skip(self))]`
//! on `MeteredEphemeralStore` methods — NO `err` flag") while
//! keeping the adapter implementation of the port contract
//! identical byte-for-byte.

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tracing::instrument;

use hort_app::ephemeral_keyspace::EphemeralKeyspaceClass;
use hort_domain::error::DomainResult;
use hort_domain::ports::ephemeral_store::EphemeralStore;
use hort_domain::ports::BoxFuture;

/// Label-name constants for the ephemeral-store metrics.
mod labels {
    pub const OPERATION: &str = "operation";
    pub const RESULT: &str = "result";
    /// Routing class label — `class={evictable|durable}`.
    pub const CLASS: &str = "class";
}

/// Enumerable label values for the `operation` label.
mod op {
    pub const GET: &str = "get";
    pub const PUT: &str = "put";
    pub const PUT_IF_ABSENT: &str = "put_if_absent";
    pub const COMPARE_AND_SWAP: &str = "compare_and_swap";
    pub const DELETE: &str = "delete";
    pub const EXTEND_TTL: &str = "extend_ttl";
    /// Atomic increment-and-cap (DOS-low-2 hardening).
    pub const TRY_INCREMENT_COUNTER: &str = "try_increment_counter";
}

/// Enumerable label values for the `result` label.
mod result_label {
    pub const OK: &str = "ok";
    pub const CAS_MISS: &str = "cas_miss";
    pub const NOT_FOUND: &str = "not_found";
    pub const ERROR: &str = "error";
}

/// Metric names.
const OP_COUNTER: &str = "hort_ephemeral_store_operations_total";
const OP_DURATION: &str = "hort_ephemeral_store_operation_duration_seconds";

fn emit(operation: &'static str, result: &'static str, class: &'static str, elapsed: Duration) {
    metrics::counter!(
        OP_COUNTER,
        labels::OPERATION => operation,
        labels::RESULT => result,
        labels::CLASS => class,
    )
    .increment(1);
    metrics::histogram!(
        OP_DURATION,
        labels::OPERATION => operation,
        labels::CLASS => class,
    )
    .record(elapsed.as_secs_f64());
}

/// Metered wrapper over any [`EphemeralStore`]. Constructed by the
/// composition root after the concrete backend (memory or Redis) has
/// been wired. Cheap to clone via `Arc<dyn EphemeralStore>`.
///
/// The inner store is held behind an `Arc<T>` so the composition root
/// can hand the same physical store to two class-labelled wrappers when
/// the operator's per-class Redis URLs resolve to the same target (the
/// dominant single-Redis case). See `docs/metrics-catalog.md` for the
/// metric shapes.
pub struct MeteredEphemeralStore<T: EphemeralStore> {
    inner: Arc<T>,
    /// Routing class label string emitted on every metric series.
    /// Stored as a `&'static str` (resolved once via
    /// [`EphemeralKeyspaceClass::as_metric_label`]) so the allocation
    /// profile of the wrapper is unchanged.
    class_label: &'static str,
}

impl<T: EphemeralStore> MeteredEphemeralStore<T> {
    /// Wrap `inner` so every port call emits metrics tagged with
    /// `class={evictable|durable}`.
    ///
    /// The composition root chooses `class` per consumer at wiring
    /// time; the wrapper carries it onto every metric emission.
    /// `EphemeralKeyspaceClass` is `Copy` so the constructor takes
    /// it by value.
    pub fn new(inner: Arc<T>, class: EphemeralKeyspaceClass) -> Self {
        Self {
            inner,
            class_label: class.as_metric_label(),
        }
    }

    #[instrument(skip(self))]
    async fn get_impl(&self, key: String) -> DomainResult<Option<Bytes>> {
        let started = Instant::now();
        let outcome = self.inner.get(&key).await;
        let (ret, label) = match outcome {
            Ok(None) => (Ok(None), result_label::NOT_FOUND),
            Ok(some) => (Ok(some), result_label::OK),
            Err(e) => (Err(e), result_label::ERROR),
        };
        emit(op::GET, label, self.class_label, started.elapsed());
        ret
    }

    #[instrument(skip(self, value))]
    async fn put_impl(&self, key: String, value: Bytes, ttl: Duration) -> DomainResult<()> {
        let started = Instant::now();
        let outcome = self.inner.put(&key, value, ttl).await;
        let label = if outcome.is_ok() {
            result_label::OK
        } else {
            result_label::ERROR
        };
        emit(op::PUT, label, self.class_label, started.elapsed());
        outcome
    }

    #[instrument(skip(self, value))]
    async fn put_if_absent_impl(
        &self,
        key: String,
        value: Bytes,
        ttl: Duration,
    ) -> DomainResult<bool> {
        let started = Instant::now();
        let outcome = self.inner.put_if_absent(&key, value, ttl).await;
        let (ret, label) = match outcome {
            Ok(true) => (Ok(true), result_label::OK),
            // Collision is the `put_if_absent` analogue of a CAS
            // miss — not "error", not "ok". Sharing the
            // `cas_miss` label keeps the taxonomy small and
            // surfaces contention on the same time-series panel.
            Ok(false) => (Ok(false), result_label::CAS_MISS),
            Err(e) => (Err(e), result_label::ERROR),
        };
        emit(
            op::PUT_IF_ABSENT,
            label,
            self.class_label,
            started.elapsed(),
        );
        ret
    }

    #[instrument(skip(self, new_value), fields(expected = expected_version))]
    async fn compare_and_swap_impl(
        &self,
        key: String,
        expected_version: u64,
        new_value: Bytes,
        ttl: Duration,
    ) -> DomainResult<Option<u64>> {
        let started = Instant::now();
        let outcome = self
            .inner
            .compare_and_swap(&key, expected_version, new_value, ttl)
            .await;
        let (ret, label) = match outcome {
            Ok(Some(v)) => (Ok(Some(v)), result_label::OK),
            Ok(None) => (Ok(None), result_label::CAS_MISS),
            Err(e) => (Err(e), result_label::ERROR),
        };
        emit(
            op::COMPARE_AND_SWAP,
            label,
            self.class_label,
            started.elapsed(),
        );
        ret
    }

    #[instrument(skip(self))]
    async fn delete_impl(&self, key: String) -> DomainResult<()> {
        // Port contract says delete on an absent key is Ok(()), and the
        // backend itself does not signal whether the key existed before
        // the call. We previously probed via `get` to differentiate `ok`
        // from `not_found` for diagnostic value, but on the OCI finalize
        // hot path that doubles the round-trip cost against Redis.
        // Collapsed to a single label: success is `ok`, propagated error
        // is `error`. Operators get the genuine-delete vs idempotent
        // re-delete signal from upstream business metrics
        // (`hort_stateful_upload_sessions_total{result="finalized"}` /
        // `result="aborted"`) which already discriminate the call site.
        let started = Instant::now();
        let outcome = self.inner.delete(&key).await;
        let label = match &outcome {
            Ok(()) => result_label::OK,
            Err(_) => result_label::ERROR,
        };
        emit(op::DELETE, label, self.class_label, started.elapsed());
        outcome
    }

    #[instrument(skip(self))]
    async fn extend_ttl_impl(&self, key: String, ttl: Duration) -> DomainResult<()> {
        // Same rationale as `delete`: drop the pre-probe round-trip.
        let started = Instant::now();
        let outcome = self.inner.extend_ttl(&key, ttl).await;
        let label = match &outcome {
            Ok(()) => result_label::OK,
            Err(_) => result_label::ERROR,
        };
        emit(op::EXTEND_TTL, label, self.class_label, started.elapsed());
        outcome
    }

    #[instrument(skip(self), fields(max = max))]
    async fn try_increment_counter_impl(
        &self,
        key: String,
        max: u64,
        ttl: Duration,
    ) -> DomainResult<Option<u64>> {
        let started = Instant::now();
        let outcome = self.inner.try_increment_counter(&key, max, ttl).await;
        // Cap-rejected (`Ok(None)`) is the analogue of `cas_miss` —
        // not "error", not "ok". Sharing the existing label keeps
        // the taxonomy small and surfaces cap pressure on the same
        // panel as CAS contention.
        let (ret, label) = match outcome {
            Ok(Some(v)) => (Ok(Some(v)), result_label::OK),
            Ok(None) => (Ok(None), result_label::CAS_MISS),
            Err(e) => (Err(e), result_label::ERROR),
        };
        emit(
            op::TRY_INCREMENT_COUNTER,
            label,
            self.class_label,
            started.elapsed(),
        );
        ret
    }
}

impl<T: EphemeralStore> EphemeralStore for MeteredEphemeralStore<T> {
    fn get(&self, key: &str) -> BoxFuture<'_, DomainResult<Option<Bytes>>> {
        Box::pin(self.get_impl(key.to_owned()))
    }

    fn put(&self, key: &str, value: Bytes, ttl: Duration) -> BoxFuture<'_, DomainResult<()>> {
        Box::pin(self.put_impl(key.to_owned(), value, ttl))
    }

    fn put_if_absent(
        &self,
        key: &str,
        value: Bytes,
        ttl: Duration,
    ) -> BoxFuture<'_, DomainResult<bool>> {
        Box::pin(self.put_if_absent_impl(key.to_owned(), value, ttl))
    }

    fn compare_and_swap(
        &self,
        key: &str,
        expected_version: u64,
        new_value: Bytes,
        ttl: Duration,
    ) -> BoxFuture<'_, DomainResult<Option<u64>>> {
        Box::pin(self.compare_and_swap_impl(key.to_owned(), expected_version, new_value, ttl))
    }

    fn delete(&self, key: &str) -> BoxFuture<'_, DomainResult<()>> {
        Box::pin(self.delete_impl(key.to_owned()))
    }

    fn extend_ttl(&self, key: &str, ttl: Duration) -> BoxFuture<'_, DomainResult<()>> {
        Box::pin(self.extend_ttl_impl(key.to_owned(), ttl))
    }

    fn try_increment_counter(
        &self,
        key: &str,
        max: u64,
        ttl: Duration,
    ) -> BoxFuture<'_, DomainResult<Option<u64>>> {
        Box::pin(self.try_increment_counter_impl(key.to_owned(), max, ttl))
    }
}

#[cfg(test)]
mod tests {
    use metrics::{SharedString, Unit};
    use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
    use metrics_util::CompositeKey;

    use crate::InMemoryEphemeralStore;

    use super::*;

    type SnapshotRow = (CompositeKey, Option<Unit>, Option<SharedString>, DebugValue);

    /// Capture metrics emitted by the async block by installing a
    /// local recorder for the duration of the closure. A nested
    /// current-thread runtime drives the async code because
    /// `metrics::with_local_recorder` takes a sync closure. Pattern
    /// mirrors `hort-adapters-storage::filesystem::tests::capture_async`.
    fn capture<F, Fut>(f: F) -> Vec<SnapshotRow>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let recorder = DebuggingRecorder::new();
        let snapshotter: Snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(f());
        });
        snapshotter.snapshot().into_vec()
    }

    /// Lookup the value of `hort_ephemeral_store_operations_total` for
    /// the `(operation, result)` label pair, or `0` if no series.
    fn counter_for(rows: &[SnapshotRow], operation: &str, result: &str) -> u64 {
        for (ckey, _unit, _desc, value) in rows {
            let key = ckey.key();
            if key.name() != OP_COUNTER {
                continue;
            }
            let mut op_ok = false;
            let mut res_ok = false;
            for label in key.labels() {
                if label.key() == labels::OPERATION && label.value() == operation {
                    op_ok = true;
                }
                if label.key() == labels::RESULT && label.value() == result {
                    res_ok = true;
                }
            }
            if op_ok && res_ok {
                if let DebugValue::Counter(n) = value {
                    return *n;
                }
            }
        }
        0
    }

    /// Lookup the value of `hort_ephemeral_store_operations_total` for
    /// the `(operation, result, class)` label triple. Returns `0` if
    /// no matching series. Verifies the routing `class` label is
    /// threaded onto every emission.
    fn counter_for_class(rows: &[SnapshotRow], operation: &str, result: &str, class: &str) -> u64 {
        for (ckey, _unit, _desc, value) in rows {
            let key = ckey.key();
            if key.name() != OP_COUNTER {
                continue;
            }
            let mut op_ok = false;
            let mut res_ok = false;
            let mut class_ok = false;
            for label in key.labels() {
                if label.key() == labels::OPERATION && label.value() == operation {
                    op_ok = true;
                }
                if label.key() == labels::RESULT && label.value() == result {
                    res_ok = true;
                }
                if label.key() == labels::CLASS && label.value() == class {
                    class_ok = true;
                }
            }
            if op_ok && res_ok && class_ok {
                if let DebugValue::Counter(n) = value {
                    return *n;
                }
            }
        }
        0
    }

    /// Returns `true` if the histogram series
    /// `hort_ephemeral_store_operation_duration_seconds{operation, class}`
    /// recorded at least one observation. The routing `class` label
    /// must reach the histogram too, not only the counter.
    fn histogram_recorded(rows: &[SnapshotRow], operation: &str, class: &str) -> bool {
        for (ckey, _unit, _desc, value) in rows {
            let key = ckey.key();
            if key.name() != OP_DURATION {
                continue;
            }
            let mut op_ok = false;
            let mut class_ok = false;
            for label in key.labels() {
                if label.key() == labels::OPERATION && label.value() == operation {
                    op_ok = true;
                }
                if label.key() == labels::CLASS && label.value() == class {
                    class_ok = true;
                }
            }
            if op_ok && class_ok {
                if let DebugValue::Histogram(samples) = value {
                    if !samples.is_empty() {
                        return true;
                    }
                }
            }
        }
        false
    }

    #[test]
    fn get_absent_emits_not_found() {
        let snap = capture(|| async {
            let store = MeteredEphemeralStore::new(
                Arc::new(InMemoryEphemeralStore::new()),
                EphemeralKeyspaceClass::Durable,
            );
            assert!(store.get("missing").await.unwrap().is_none());
        });
        assert_eq!(counter_for(&snap, op::GET, result_label::NOT_FOUND), 1);
    }

    #[test]
    fn put_ok_emits_ok() {
        let snap = capture(|| async {
            let store = MeteredEphemeralStore::new(
                Arc::new(InMemoryEphemeralStore::new()),
                EphemeralKeyspaceClass::Durable,
            );
            store
                .put("k", Bytes::from_static(b"v"), Duration::from_secs(60))
                .await
                .unwrap();
        });
        assert_eq!(counter_for(&snap, op::PUT, result_label::OK), 1);
    }

    #[test]
    fn get_hit_emits_ok() {
        let snap = capture(|| async {
            let store = MeteredEphemeralStore::new(
                Arc::new(InMemoryEphemeralStore::new()),
                EphemeralKeyspaceClass::Durable,
            );
            store
                .put("k", Bytes::from_static(b"v"), Duration::from_secs(60))
                .await
                .unwrap();
            assert_eq!(
                store.get("k").await.unwrap(),
                Some(Bytes::from_static(b"v"))
            );
        });
        assert_eq!(counter_for(&snap, op::GET, result_label::OK), 1);
    }

    #[test]
    fn put_if_absent_collision_emits_cas_miss() {
        let snap = capture(|| async {
            let store = MeteredEphemeralStore::new(
                Arc::new(InMemoryEphemeralStore::new()),
                EphemeralKeyspaceClass::Durable,
            );
            assert!(store
                .put_if_absent("k", Bytes::from_static(b"v1"), Duration::from_secs(60))
                .await
                .unwrap());
            assert!(!store
                .put_if_absent("k", Bytes::from_static(b"v2"), Duration::from_secs(60))
                .await
                .unwrap());
        });
        assert_eq!(
            counter_for(&snap, op::PUT_IF_ABSENT, result_label::OK),
            1,
            "first call is ok"
        );
        assert_eq!(
            counter_for(&snap, op::PUT_IF_ABSENT, result_label::CAS_MISS),
            1,
            "second call is cas_miss"
        );
    }

    #[test]
    fn cas_miss_emits_cas_miss() {
        let snap = capture(|| async {
            let store = MeteredEphemeralStore::new(
                Arc::new(InMemoryEphemeralStore::new()),
                EphemeralKeyspaceClass::Durable,
            );
            store
                .put("k", Bytes::from_static(b"v"), Duration::from_secs(60))
                .await
                .unwrap();
            assert_eq!(
                store
                    .compare_and_swap("k", 999, Bytes::from_static(b"x"), Duration::from_secs(60))
                    .await
                    .unwrap(),
                None
            );
        });
        assert_eq!(
            counter_for(&snap, op::COMPARE_AND_SWAP, result_label::CAS_MISS),
            1
        );
    }

    #[test]
    fn cas_hit_emits_ok() {
        let snap = capture(|| async {
            let store = MeteredEphemeralStore::new(
                Arc::new(InMemoryEphemeralStore::new()),
                EphemeralKeyspaceClass::Durable,
            );
            store
                .put("k", Bytes::from_static(b"v1"), Duration::from_secs(60))
                .await
                .unwrap();
            assert_eq!(
                store
                    .compare_and_swap("k", 1, Bytes::from_static(b"v2"), Duration::from_secs(60))
                    .await
                    .unwrap(),
                Some(2)
            );
        });
        assert_eq!(
            counter_for(&snap, op::COMPARE_AND_SWAP, result_label::OK),
            1
        );
    }

    #[test]
    fn delete_present_emits_ok() {
        let snap = capture(|| async {
            let store = MeteredEphemeralStore::new(
                Arc::new(InMemoryEphemeralStore::new()),
                EphemeralKeyspaceClass::Durable,
            );
            store
                .put("k", Bytes::from_static(b"v"), Duration::from_secs(60))
                .await
                .unwrap();
            store.delete("k").await.unwrap();
        });
        assert_eq!(counter_for(&snap, op::DELETE, result_label::OK), 1);
    }

    #[test]
    fn delete_absent_emits_ok() {
        // Port contract: delete on an absent key is Ok(()). The wrapper
        // no longer probes `get` first to differentiate `not_found` —
        // operators get the genuine vs idempotent signal from upstream
        // business metrics. Both presence states fold to `ok`.
        let snap = capture(|| async {
            let store = MeteredEphemeralStore::new(
                Arc::new(InMemoryEphemeralStore::new()),
                EphemeralKeyspaceClass::Durable,
            );
            store.delete("never-written").await.unwrap();
        });
        assert_eq!(counter_for(&snap, op::DELETE, result_label::OK), 1);
        assert_eq!(counter_for(&snap, op::DELETE, result_label::NOT_FOUND), 0);
    }

    #[test]
    fn extend_ttl_present_emits_ok() {
        let snap = capture(|| async {
            let store = MeteredEphemeralStore::new(
                Arc::new(InMemoryEphemeralStore::new()),
                EphemeralKeyspaceClass::Durable,
            );
            store
                .put("k", Bytes::from_static(b"v"), Duration::from_secs(60))
                .await
                .unwrap();
            store
                .extend_ttl("k", Duration::from_secs(120))
                .await
                .unwrap();
        });
        assert_eq!(counter_for(&snap, op::EXTEND_TTL, result_label::OK), 1);
    }

    #[test]
    fn extend_ttl_absent_emits_ok() {
        // See delete_absent_emits_ok — same rationale.
        let snap = capture(|| async {
            let store = MeteredEphemeralStore::new(
                Arc::new(InMemoryEphemeralStore::new()),
                EphemeralKeyspaceClass::Durable,
            );
            store
                .extend_ttl("never-written", Duration::from_secs(60))
                .await
                .unwrap();
        });
        assert_eq!(counter_for(&snap, op::EXTEND_TTL, result_label::OK), 1);
        assert_eq!(
            counter_for(&snap, op::EXTEND_TTL, result_label::NOT_FOUND),
            0
        );
    }

    // ──────────────────────────────────────────────────────────────
    // Routing `class` label assertions
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn evictable_class_threads_evictable_label_onto_counter_and_histogram() {
        let snap = capture(|| async {
            let store = MeteredEphemeralStore::new(
                Arc::new(InMemoryEphemeralStore::new()),
                EphemeralKeyspaceClass::Evictable,
            );
            store
                .put("k", Bytes::from_static(b"v"), Duration::from_secs(60))
                .await
                .unwrap();
        });
        // Counter carries class="evictable".
        assert_eq!(
            counter_for_class(&snap, op::PUT, result_label::OK, "evictable"),
            1,
            "evictable wrapper must emit class=\"evictable\" on the counter",
        );
        // Same series MUST NOT also emit class="durable".
        assert_eq!(
            counter_for_class(&snap, op::PUT, result_label::OK, "durable"),
            0,
            "evictable wrapper must not emit class=\"durable\"",
        );
        // Histogram carries class="evictable".
        assert!(
            histogram_recorded(&snap, op::PUT, "evictable"),
            "evictable wrapper must record histogram with class=\"evictable\"",
        );
        // Existing operation/result labels remain populated (regression guard:
        // adding `class` did not displace the prior taxonomy).
        assert_eq!(
            counter_for(&snap, op::PUT, result_label::OK),
            1,
            "operation and result labels must still be emitted",
        );
    }

    #[test]
    fn durable_class_threads_durable_label_onto_counter_and_histogram() {
        let snap = capture(|| async {
            let store = MeteredEphemeralStore::new(
                Arc::new(InMemoryEphemeralStore::new()),
                EphemeralKeyspaceClass::Durable,
            );
            store
                .put("k", Bytes::from_static(b"v"), Duration::from_secs(60))
                .await
                .unwrap();
        });
        assert_eq!(
            counter_for_class(&snap, op::PUT, result_label::OK, "durable"),
            1,
            "durable wrapper must emit class=\"durable\" on the counter",
        );
        assert_eq!(
            counter_for_class(&snap, op::PUT, result_label::OK, "evictable"),
            0,
            "durable wrapper must not emit class=\"evictable\"",
        );
        assert!(
            histogram_recorded(&snap, op::PUT, "durable"),
            "durable wrapper must record histogram with class=\"durable\"",
        );
    }

    #[test]
    fn class_label_threads_through_get_and_delete_too() {
        // Spot-check: every emission site (not just `put`) carries the
        // class label. `get` against an absent key emits `not_found`;
        // `delete` against an absent key emits `ok`. Both emissions
        // must carry the configured class.
        let snap = capture(|| async {
            let store = MeteredEphemeralStore::new(
                Arc::new(InMemoryEphemeralStore::new()),
                EphemeralKeyspaceClass::Evictable,
            );
            assert!(store.get("missing").await.unwrap().is_none());
            store.delete("missing").await.unwrap();
        });
        assert_eq!(
            counter_for_class(&snap, op::GET, result_label::NOT_FOUND, "evictable"),
            1,
        );
        assert_eq!(
            counter_for_class(&snap, op::DELETE, result_label::OK, "evictable"),
            1,
        );
    }
}
