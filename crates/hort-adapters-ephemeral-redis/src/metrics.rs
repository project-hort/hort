//! `MeteredEphemeralStore` — wrapper that forwards every call to an
//! inner [`EphemeralStore`] and emits the `hort_ephemeral_store_*`
//! metric pair on every operation.
//!
//! Intentionally duplicated from `hort-adapters-ephemeral-memory::metrics`
//! (~120 LOC). The alternative — a shared `hort-adapters-ephemeral-core`
//! crate carrying the wrapper — pulls both adapter crates into the
//! same compilation unit and trades one shared-helper crate for the
//! same duplication in `Cargo.toml` dependency edges. Duplicating the
//! thin wrapper keeps each adapter's dependency graph minimal and
//! makes per-adapter evolution (e.g. a Redis-specific label) cheap.
//!
//! Metric catalog (`docs/metrics-catalog.md`): `hort_ephemeral_store_operations_total`,
//! `hort_ephemeral_store_operation_duration_seconds`. Bounded label
//! sets: `operation` ∈ {get, put, put_if_absent, compare_and_swap,
//! delete, extend_ttl, try_increment_counter}. `result` ∈ {ok,
//! cas_miss, not_found, error}. `class` ∈ {evictable, durable}
//! (ephemeral-store routing class — see `docs/metrics-catalog.md`).

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tracing::instrument;

use hort_app::ephemeral_keyspace::EphemeralKeyspaceClass;
use hort_domain::error::DomainResult;
use hort_domain::ports::ephemeral_store::EphemeralStore;
use hort_domain::ports::BoxFuture;

mod labels {
    pub const OPERATION: &str = "operation";
    pub const RESULT: &str = "result";
    /// Routing class label — `class={evictable|durable}`.
    pub const CLASS: &str = "class";
}

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

mod result_label {
    pub const OK: &str = "ok";
    pub const CAS_MISS: &str = "cas_miss";
    pub const NOT_FOUND: &str = "not_found";
    pub const ERROR: &str = "error";
}

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

/// Metered wrapper over any [`EphemeralStore`]. Cheap to clone via
/// `Arc<dyn EphemeralStore>`.
///
/// The `_impl` helpers carry the `#[tracing::instrument]` attribute
/// — placing the attribute on the `BoxFuture`-returning trait method
/// directly conflicts with multi-input lifetime elision. See the
/// memory adapter's metrics module for the full rationale.
///
/// The inner store is held behind an `Arc<T>` so the composition root
/// can hand the same physical store to two class-labelled wrappers when
/// the operator's per-class Redis URLs resolve to the same target (the
/// dominant single-Redis case).
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
        // Drop the pre-probe via `get` that previously differentiated
        // `not_found` from `ok` — on the OCI finalize hot path it
        // doubled the round-trip cost against Redis. Operators get the
        // genuine vs idempotent signal from upstream business metrics
        // (`hort_stateful_upload_sessions_total`) which already
        // discriminate the call site. Both presence states fold to
        // `ok`; only propagated infrastructure errors emit `error`.
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
        // Cap-rejected (`Ok(None)`) is the analogue of `cas_miss`.
        // Same rationale as the memory adapter's wrapper.
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
    //! Unit tests for [`MeteredEphemeralStore`] in the Redis adapter
    //! crate. Verifies the routing `class={evictable|durable}` label is
    //! threaded onto every metric series, regardless of which port
    //! operation drives the emission.
    //!
    //! We do NOT need a real Redis client to exercise the wrapper —
    //! the metric emission lives entirely inside `MeteredEphemeralStore`,
    //! independent of the inner adapter. A minimal stub `EphemeralStore`
    //! that returns hard-coded outcomes is sufficient. The full
    //! redis-backed integration suite lives in `tests/contract.rs` and
    //! is gated behind the `redis-integration-tests` feature.
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    use hort_domain::error::{DomainError, DomainResult};
    use metrics::{SharedString, Unit};
    use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
    use metrics_util::CompositeKey;

    use super::*;

    type SnapshotRow = (CompositeKey, Option<Unit>, Option<SharedString>, DebugValue);

    /// Capture metrics emitted by the async block by installing a
    /// local recorder for the duration of the closure. Mirrors the
    /// memory adapter's `capture` helper.
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
    /// the `(operation, result, class)` label triple.
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
    /// recorded at least one observation.
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

    /// Minimal in-memory stub implementation of [`EphemeralStore`].
    /// Used only by these unit tests to drive [`MeteredEphemeralStore`]
    /// without requiring a Redis sidecar. Behaviour is just enough to
    /// produce well-defined `result` labels (`ok`, `not_found`,
    /// `cas_miss`, `error`) so the class-label assertions are
    /// orthogonal to the chosen `result`.
    struct StubStore {
        items: Mutex<std::collections::HashMap<String, (Bytes, u64)>>,
        version_seq: AtomicU64,
        fail_next: AtomicU64,
    }

    impl StubStore {
        fn new() -> Self {
            Self {
                items: Mutex::new(std::collections::HashMap::new()),
                version_seq: AtomicU64::new(0),
                fail_next: AtomicU64::new(0),
            }
        }

        /// Make the next port call return `DomainError::Invariant`,
        /// so the wrapper emits `result="error"`.
        fn fail_once(&self) {
            self.fail_next.store(1, Ordering::SeqCst);
        }

        fn maybe_fail(&self) -> DomainResult<()> {
            if self
                .fail_next
                .compare_exchange(1, 0, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                Err(DomainError::Invariant("injected".into()))
            } else {
                Ok(())
            }
        }
    }

    impl EphemeralStore for StubStore {
        fn get(&self, key: &str) -> BoxFuture<'_, DomainResult<Option<Bytes>>> {
            let key = key.to_owned();
            Box::pin(async move {
                self.maybe_fail()?;
                Ok(self.items.lock().unwrap().get(&key).map(|(v, _)| v.clone()))
            })
        }

        fn put(&self, key: &str, value: Bytes, _ttl: Duration) -> BoxFuture<'_, DomainResult<()>> {
            let key = key.to_owned();
            Box::pin(async move {
                self.maybe_fail()?;
                let v = self.version_seq.fetch_add(1, Ordering::SeqCst) + 1;
                self.items.lock().unwrap().insert(key, (value, v));
                Ok(())
            })
        }

        fn put_if_absent(
            &self,
            key: &str,
            value: Bytes,
            _ttl: Duration,
        ) -> BoxFuture<'_, DomainResult<bool>> {
            let key = key.to_owned();
            Box::pin(async move {
                self.maybe_fail()?;
                let mut g = self.items.lock().unwrap();
                if g.contains_key(&key) {
                    return Ok(false);
                }
                let v = self.version_seq.fetch_add(1, Ordering::SeqCst) + 1;
                g.insert(key, (value, v));
                Ok(true)
            })
        }

        fn compare_and_swap(
            &self,
            key: &str,
            expected_version: u64,
            new_value: Bytes,
            _ttl: Duration,
        ) -> BoxFuture<'_, DomainResult<Option<u64>>> {
            let key = key.to_owned();
            Box::pin(async move {
                self.maybe_fail()?;
                let mut g = self.items.lock().unwrap();
                match g.get(&key) {
                    Some((_, v)) if *v == expected_version => {
                        let nv = self.version_seq.fetch_add(1, Ordering::SeqCst) + 1;
                        g.insert(key, (new_value, nv));
                        Ok(Some(nv))
                    }
                    _ => Ok(None),
                }
            })
        }

        fn delete(&self, key: &str) -> BoxFuture<'_, DomainResult<()>> {
            let key = key.to_owned();
            Box::pin(async move {
                self.maybe_fail()?;
                self.items.lock().unwrap().remove(&key);
                Ok(())
            })
        }

        fn extend_ttl(&self, _key: &str, _ttl: Duration) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async move {
                self.maybe_fail()?;
                Ok(())
            })
        }
    }

    #[test]
    fn evictable_class_threads_evictable_label_onto_counter_and_histogram() {
        let snap = capture(|| async {
            let store = MeteredEphemeralStore::new(
                Arc::new(StubStore::new()),
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
    }

    #[test]
    fn durable_class_threads_durable_label_onto_counter_and_histogram() {
        let snap = capture(|| async {
            let store = MeteredEphemeralStore::new(
                Arc::new(StubStore::new()),
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
    fn existing_operation_and_result_labels_remain_emitted() {
        // Regression guard: adding `class` did not displace the
        // prior taxonomy. We exercise multiple operations and result
        // values to make sure every emission site still carries
        // (operation, result) — independent of class.
        let snap = capture(|| async {
            let store = MeteredEphemeralStore::new(
                Arc::new(StubStore::new()),
                EphemeralKeyspaceClass::Durable,
            );
            // op=put result=ok
            store
                .put("k", Bytes::from_static(b"v1"), Duration::from_secs(60))
                .await
                .unwrap();
            // op=get result=ok
            assert_eq!(
                store.get("k").await.unwrap(),
                Some(Bytes::from_static(b"v1"))
            );
            // op=get result=not_found
            assert!(store.get("missing").await.unwrap().is_none());
            // op=put_if_absent result=cas_miss
            assert!(!store
                .put_if_absent("k", Bytes::from_static(b"v2"), Duration::from_secs(60))
                .await
                .unwrap());
            // op=delete result=ok
            store.delete("k").await.unwrap();
        });

        // Every emission carries class="durable" (regression guard
        // — class label threading is universal).
        assert_eq!(
            counter_for_class(&snap, op::PUT, result_label::OK, "durable"),
            1,
        );
        assert_eq!(
            counter_for_class(&snap, op::GET, result_label::OK, "durable"),
            1,
        );
        assert_eq!(
            counter_for_class(&snap, op::GET, result_label::NOT_FOUND, "durable"),
            1,
        );
        assert_eq!(
            counter_for_class(&snap, op::PUT_IF_ABSENT, result_label::CAS_MISS, "durable"),
            1,
        );
        assert_eq!(
            counter_for_class(&snap, op::DELETE, result_label::OK, "durable"),
            1,
        );
    }

    #[test]
    fn error_path_also_carries_class_label() {
        // The wrapper must thread class through the error branch too,
        // not just the happy path.
        let snap = capture(|| async {
            let stub = Arc::new(StubStore::new());
            stub.fail_once();
            let store = MeteredEphemeralStore::new(stub, EphemeralKeyspaceClass::Evictable);
            // The failure surfaces as `result=error`.
            assert!(store
                .put("k", Bytes::from_static(b"v"), Duration::from_secs(60))
                .await
                .is_err());
        });
        assert_eq!(
            counter_for_class(&snap, op::PUT, result_label::ERROR, "evictable"),
            1,
            "error path must still emit the class label",
        );
    }
}
