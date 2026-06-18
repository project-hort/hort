//! Port-contract suite for `EphemeralStore`.
//!
//! These are integration tests rather than lib tests so the Redis
//! adapter's integration test (`hort-adapters-ephemeral-redis/tests/`)
//! can copy the same assertions without an awkward cross-crate
//! `#[path]` import — ~150 LOC of duplication is cheaper than a
//! shared test-helper crate.
//!
//! Every case exercises the trait through `&dyn EphemeralStore` so
//! the wrapping `MeteredEphemeralStore` isn't short-circuited. The
//! wrapper's metric emission has its own unit tests in
//! `src/metrics.rs`; these tests only care about the port contract.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use hort_adapters_ephemeral_memory::{InMemoryEphemeralStore, MeteredEphemeralStore};
use hort_app::ephemeral_keyspace::EphemeralKeyspaceClass;
use hort_domain::ports::ephemeral_store::EphemeralStore;

/// Build the adapter-under-test. Wrapping keeps the metric surface
/// in the call graph — any future regression that breaks the
/// wrapper's forwarding (e.g. eager collection, dropped futures)
/// shows up here rather than only in the metrics unit tests.
fn store() -> Arc<dyn EphemeralStore> {
    Arc::new(MeteredEphemeralStore::new(
        Arc::new(InMemoryEphemeralStore::new()),
        // TODO: replace with proper class assignment in composition rewire.
        // Contract tests do not care about the class label (they exercise the port
        // semantics, not metric emission); `Durable` is the safer default.
        EphemeralKeyspaceClass::Durable,
    ))
}

const TTL_LONG: Duration = Duration::from_secs(60);
const TTL_SHORT: Duration = Duration::from_millis(200);
const TTL_MEDIUM: Duration = Duration::from_millis(500);

#[tokio::test]
async fn get_absent_returns_none() {
    let s = store();
    assert!(s.get("missing").await.unwrap().is_none());
}

#[tokio::test]
async fn put_then_get_roundtrips() {
    let s = store();
    s.put("k", Bytes::from_static(b"v"), TTL_LONG)
        .await
        .unwrap();
    assert_eq!(s.get("k").await.unwrap(), Some(Bytes::from_static(b"v")));
}

#[tokio::test]
async fn put_if_absent_returns_false_on_collision() {
    let s = store();
    let first = s
        .put_if_absent("k", Bytes::from_static(b"v1"), TTL_LONG)
        .await
        .unwrap();
    assert!(first, "first put_if_absent must win");

    let second = s
        .put_if_absent("k", Bytes::from_static(b"v2"), TTL_LONG)
        .await
        .unwrap();
    assert!(!second, "second put_if_absent must see the collision");

    assert_eq!(s.get("k").await.unwrap(), Some(Bytes::from_static(b"v1")));
}

#[tokio::test]
async fn cas_with_wrong_version_returns_none() {
    let s = store();
    s.put("k", Bytes::from_static(b"v"), TTL_LONG)
        .await
        .unwrap();
    // First put is version = 1; CAS with 999 must fail.
    let outcome = s
        .compare_and_swap("k", 999, Bytes::from_static(b"other"), TTL_LONG)
        .await
        .unwrap();
    assert_eq!(outcome, None);
    assert_eq!(s.get("k").await.unwrap(), Some(Bytes::from_static(b"v")));
}

#[tokio::test]
async fn cas_with_right_version_returns_new_version() {
    let s = store();
    s.put("k", Bytes::from_static(b"v1"), TTL_LONG)
        .await
        .unwrap();

    let first = s
        .compare_and_swap("k", 1, Bytes::from_static(b"v2"), TTL_LONG)
        .await
        .unwrap();
    assert_eq!(first, Some(2));

    // A second CAS from the same caller still holding v1 must fail.
    let stale = s
        .compare_and_swap("k", 1, Bytes::from_static(b"v3"), TTL_LONG)
        .await
        .unwrap();
    assert_eq!(stale, None);

    // Value reflects the successful CAS.
    assert_eq!(s.get("k").await.unwrap(), Some(Bytes::from_static(b"v2")));
}

#[tokio::test]
async fn extend_ttl_preserves_value_and_pushes_expiry() {
    let s = store();
    s.put("k", Bytes::from_static(b"v"), TTL_MEDIUM)
        .await
        .unwrap();

    // Extend well before expiry.
    s.extend_ttl("k", Duration::from_secs(10)).await.unwrap();

    tokio::time::sleep(Duration::from_secs(1)).await;

    assert_eq!(s.get("k").await.unwrap(), Some(Bytes::from_static(b"v")));
}

#[tokio::test]
async fn delete_then_get_returns_none() {
    let s = store();
    s.put("k", Bytes::from_static(b"v"), TTL_LONG)
        .await
        .unwrap();
    s.delete("k").await.unwrap();
    assert!(s.get("k").await.unwrap().is_none());
}

#[tokio::test]
async fn ttl_expiry_evicts_value() {
    let s = store();
    s.put("k", Bytes::from_static(b"v"), TTL_SHORT)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(s.get("k").await.unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_cas_exactly_one_wins() {
    let s = Arc::new(MeteredEphemeralStore::new(
        Arc::new(InMemoryEphemeralStore::new()),
        // TODO: replace with proper class assignment in composition rewire.
        EphemeralKeyspaceClass::Durable,
    ));
    // Seed version = 1.
    s.put("race", Bytes::from_static(b"init"), TTL_LONG)
        .await
        .unwrap();

    let mut handles = Vec::with_capacity(10);
    for i in 0..10 {
        let s = Arc::clone(&s);
        handles.push(tokio::spawn(async move {
            let payload = Bytes::from(format!("payload-{i}"));
            s.compare_and_swap("race", 1, payload, TTL_LONG).await
        }));
    }

    let mut wins = 0;
    let mut losses = 0;
    for h in handles {
        match h.await.unwrap().unwrap() {
            Some(_) => wins += 1,
            None => losses += 1,
        }
    }
    assert_eq!(wins, 1, "exactly one CAS must win");
    assert_eq!(losses, 9, "nine CAS must see a version mismatch");
}
