//! Port-contract suite for the Redis [`EphemeralStore`] adapter.
//!
//! Duplicates the structure of `hort-adapters-ephemeral-memory/tests/contract.rs`
//! because sharing the suite via a test-helper crate is more
//! machinery than it's worth for ~150 LOC. Every case issued here
//! must continue to pass against the memory adapter — the two
//! adapters are functionally interchangeable at the port surface.
//!
//! **Gated** behind the `redis-integration-tests` feature and the
//! `HORT_REDIS_URL` env var. The default `cargo test` / Fast-CI run
//! compiles this file but produces **zero runnable tests** — each
//! case early-returns with an `eprintln!` describing the skip
//! reason so CI logs surface that Redis coverage was skipped.
//! Opt-in:
//!
//! ```bash
//! HORT_REDIS_URL=redis://localhost:6379/0 \
//!   cargo test -p hort-adapters-ephemeral-redis --features redis-integration-tests
//! ```

#![cfg(feature = "redis-integration-tests")]

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use hort_adapters_ephemeral_redis::{MeteredEphemeralStore, RedisEphemeralStore};
use hort_app::ephemeral_keyspace::EphemeralKeyspaceClass;
use hort_domain::ports::ephemeral_store::EphemeralStore;
use uuid::Uuid;

const TTL_LONG: Duration = Duration::from_secs(60);
const TTL_SHORT_MS: u64 = 1_100;

/// Return a unique key namespaced to this test run so concurrent
/// `cargo test` instances (and flaky CI runs) don't collide on
/// shared Redis state.
fn key(base: &str) -> String {
    format!("hort:test:{}:{}:{base}", std::process::id(), Uuid::new_v4())
}

/// Build the adapter-under-test, or skip the case loudly if Redis
/// is unreachable / the env var is unset.
async fn store() -> Option<Arc<dyn EphemeralStore>> {
    let url = match std::env::var("HORT_REDIS_URL") {
        Ok(u) if !u.is_empty() => u,
        _ => {
            eprintln!(
                "SKIP: HORT_REDIS_URL unset; set it to a reachable Redis \
                 instance to exercise the Redis adapter contract"
            );
            return None;
        }
    };
    match RedisEphemeralStore::connect(&url).await {
        Ok(inner) => Some(Arc::new(MeteredEphemeralStore::new(
            Arc::new(inner),
            // TODO: replace with proper class assignment in composition rewire.
            // Contract tests do not care about the class label; `Durable` is the
            // safer default.
            EphemeralKeyspaceClass::Durable,
        ))),
        Err(e) => {
            eprintln!(
                "SKIP: Redis connection failed at {url}: {e} — check that \
                 the sidecar is up"
            );
            None
        }
    }
}

#[tokio::test]
async fn get_absent_returns_none() {
    let Some(s) = store().await else {
        return;
    };
    assert!(s.get(&key("missing")).await.unwrap().is_none());
}

#[tokio::test]
async fn put_then_get_roundtrips() {
    let Some(s) = store().await else {
        return;
    };
    let k = key("roundtrip");
    s.put(&k, Bytes::from_static(b"v"), TTL_LONG).await.unwrap();
    assert_eq!(s.get(&k).await.unwrap(), Some(Bytes::from_static(b"v")));
}

#[tokio::test]
async fn put_if_absent_returns_false_on_collision() {
    let Some(s) = store().await else {
        return;
    };
    let k = key("collision");
    assert!(s
        .put_if_absent(&k, Bytes::from_static(b"v1"), TTL_LONG)
        .await
        .unwrap());
    assert!(!s
        .put_if_absent(&k, Bytes::from_static(b"v2"), TTL_LONG)
        .await
        .unwrap());
    assert_eq!(s.get(&k).await.unwrap(), Some(Bytes::from_static(b"v1")));
}

#[tokio::test]
async fn cas_with_wrong_version_returns_none() {
    let Some(s) = store().await else {
        return;
    };
    let k = key("cas-wrong");
    s.put(&k, Bytes::from_static(b"v"), TTL_LONG).await.unwrap();
    assert_eq!(
        s.compare_and_swap(&k, 999, Bytes::from_static(b"x"), TTL_LONG)
            .await
            .unwrap(),
        None
    );
    assert_eq!(s.get(&k).await.unwrap(), Some(Bytes::from_static(b"v")));
}

#[tokio::test]
async fn cas_with_right_version_returns_new_version() {
    let Some(s) = store().await else {
        return;
    };
    let k = key("cas-right");
    s.put(&k, Bytes::from_static(b"v1"), TTL_LONG)
        .await
        .unwrap();
    assert_eq!(
        s.compare_and_swap(&k, 1, Bytes::from_static(b"v2"), TTL_LONG)
            .await
            .unwrap(),
        Some(2)
    );
    assert_eq!(
        s.compare_and_swap(&k, 1, Bytes::from_static(b"v3"), TTL_LONG)
            .await
            .unwrap(),
        None
    );
    assert_eq!(s.get(&k).await.unwrap(), Some(Bytes::from_static(b"v2")));
}

#[tokio::test]
async fn extend_ttl_preserves_value_and_pushes_expiry() {
    let Some(s) = store().await else {
        return;
    };
    let k = key("extend");
    // 2-second initial TTL (Redis EXPIRE is second-grained).
    s.put(&k, Bytes::from_static(b"v"), Duration::from_secs(2))
        .await
        .unwrap();
    s.extend_ttl(&k, Duration::from_secs(60)).await.unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(s.get(&k).await.unwrap(), Some(Bytes::from_static(b"v")));
}

#[tokio::test]
async fn delete_then_get_returns_none() {
    let Some(s) = store().await else {
        return;
    };
    let k = key("delete");
    s.put(&k, Bytes::from_static(b"v"), TTL_LONG).await.unwrap();
    s.delete(&k).await.unwrap();
    assert!(s.get(&k).await.unwrap().is_none());
}

#[tokio::test]
async fn ttl_expiry_evicts_value() {
    let Some(s) = store().await else {
        return;
    };
    let k = key("expiry");
    // Redis EXPIRE is second-grained; use the shortest meaningful
    // TTL (1s) and sleep a hair longer so the expiry fires.
    s.put(&k, Bytes::from_static(b"v"), Duration::from_secs(1))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(TTL_SHORT_MS + 500)).await;
    assert!(s.get(&k).await.unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_cas_exactly_one_wins() {
    let Some(s) = store().await else {
        return;
    };
    let k = key("race");
    s.put(&k, Bytes::from_static(b"init"), TTL_LONG)
        .await
        .unwrap();

    let mut handles = Vec::with_capacity(10);
    for i in 0..10 {
        let s = Arc::clone(&s);
        let k = k.clone();
        handles.push(tokio::spawn(async move {
            let payload = Bytes::from(format!("payload-{i}"));
            s.compare_and_swap(&k, 1, payload, TTL_LONG).await
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
    assert_eq!(wins, 1);
    assert_eq!(losses, 9);
}
