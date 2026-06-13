//! Redis adapter — [`EphemeralStore`] implementation over `fred`.
//!
//! Connection is lazy: [`RedisEphemeralStore::connect`] is the
//! fallible constructor that builds the client, runs the initial
//! handshake, and installs the error-logging callback. Callers wire
//! the returned store into `AppContext.ephemeral` behind the
//! `MeteredEphemeralStore` metric wrapper — see
//! `crates/hort-server/src/composition.rs`.
//!
//! # Atomicity
//!
//! Every write path is a single `EVAL` of a Lua script so the
//! version bump, value write, and TTL refresh happen in one atomic
//! Redis operation. CAS uses the following script:
//!
//! ```lua
//! local cur = redis.call('HMGET', KEYS[1], 'v', 'val')
//! if cur[1] == ARGV[1] then
//!   local new_ver = tonumber(ARGV[1]) + 1
//!   redis.call('HSET', KEYS[1], 'v', new_ver, 'val', ARGV[2])
//!   redis.call('EXPIRE', KEYS[1], ARGV[3])
//!   return new_ver
//! end
//! return nil
//! ```

use std::time::Duration;

use bytes::Bytes;
use fred::clients::Client;
use fred::error::Error as FredError;
use fred::interfaces::{ClientLike, EventInterface, HashesInterface, KeysInterface, LuaInterface};
use fred::prelude::{Builder, Config};
use fred::types::Value as FredValue;
use tracing::{debug, warn};

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::ephemeral_store::EphemeralStore;
use hort_domain::ports::BoxFuture;

/// Version-bumping put script (unconditional write; returns the new
/// version as an integer). Reads the current version if present,
/// increments, writes value + version + TTL atomically.
///
/// ARGV[1] = value bytes, ARGV[2] = TTL seconds.
const SCRIPT_PUT: &str = r#"
local cur = redis.call('HMGET', KEYS[1], 'v')
local new_ver
if cur[1] then
  new_ver = tonumber(cur[1]) + 1
else
  new_ver = 1
end
redis.call('HSET', KEYS[1], 'v', new_ver, 'val', ARGV[1])
redis.call('EXPIRE', KEYS[1], ARGV[2])
return new_ver
"#;

/// Put-if-absent script. Returns 1 on create, 0 on collision.
/// ARGV[1] = value bytes, ARGV[2] = TTL seconds.
const SCRIPT_PUT_IF_ABSENT: &str = r#"
if redis.call('EXISTS', KEYS[1]) == 1 then
  return 0
end
redis.call('HSET', KEYS[1], 'v', 1, 'val', ARGV[1])
redis.call('EXPIRE', KEYS[1], ARGV[2])
return 1
"#;

/// CAS script — returns the new version (integer) on success, nil on
/// version mismatch. ARGV[1] = expected version (as string), ARGV[2]
/// = new value bytes, ARGV[3] = TTL seconds.
const SCRIPT_CAS: &str = r#"
local cur = redis.call('HMGET', KEYS[1], 'v', 'val')
if cur[1] == ARGV[1] then
  local new_ver = tonumber(ARGV[1]) + 1
  redis.call('HSET', KEYS[1], 'v', new_ver, 'val', ARGV[2])
  redis.call('EXPIRE', KEYS[1], ARGV[3])
  return new_ver
end
return nil
"#;

/// Atomic increment-and-cap-check (DOS-low-2 hardening).
///
/// ARGV[1] = max (as string), ARGV[2] = TTL seconds. Returns the new
/// counter value on success, nil when the increment would push the
/// counter above the cap (NO write performed in that case).
///
/// The counter is stored under the `val` field of the existing
/// `(v, val)` hash shape so the same key namespace and reads
/// continue to work via [`SCRIPT_PUT`] / [`KeysInterface::hmget`].
/// The `v` field still tracks the CAS version for parity with the
/// rest of the trait surface.
const SCRIPT_INCREMENT_WITH_CAP: &str = r#"
local cur = redis.call('HMGET', KEYS[1], 'v', 'val')
local current = 0
local cur_ver = 0
if cur[2] then
  current = tonumber(cur[2])
  if not current then
    return redis.error_reply('ephemeral counter: non-numeric value at counter key')
  end
  cur_ver = tonumber(cur[1]) or 0
end
local max = tonumber(ARGV[1])
if current >= max then
  return nil
end
local new_value = current + 1
local new_ver = cur_ver + 1
redis.call('HSET', KEYS[1], 'v', new_ver, 'val', tostring(new_value))
redis.call('EXPIRE', KEYS[1], ARGV[2])
return new_value
"#;

/// Map a `fred` error to a domain-visible [`DomainError::Invariant`].
/// The domain-layer error enum has no dedicated infrastructure
/// variant today (see `crates/hort-domain/src/error.rs`); `Invariant`
/// with a prefixed message keeps every Redis failure easy to grep
/// for without widening the domain error surface.
fn map_fred(err: &FredError) -> DomainError {
    warn!(error = %err, "redis ephemeral store failure");
    DomainError::Invariant(format!("ephemeral redis failure: {err}"))
}

fn ttl_secs(ttl: Duration) -> i64 {
    // Redis EXPIRE takes seconds. Round up so sub-second TTLs still
    // survive at least one second; callers that genuinely need
    // millisecond resolution use the memory backend.
    let raw = ttl.as_secs_f64().ceil();
    // Clamp to a safe i64 range (bounded on both ends so the cast
    // cannot overflow).
    if raw <= 0.0 {
        1
    } else if raw > i64::MAX as f64 {
        i64::MAX
    } else {
        raw as i64
    }
}

/// Redis-backed [`EphemeralStore`]. Constructed via
/// [`RedisEphemeralStore::connect`]; cheap to clone via
/// `Arc<dyn EphemeralStore>`.
pub struct RedisEphemeralStore {
    client: Client,
}

impl RedisEphemeralStore {
    /// Connect to Redis at `url` (e.g. `redis://localhost:6379/0`).
    /// Performs the initial handshake; returns a live client. A
    /// misconfigured URL or unreachable server surfaces as
    /// [`DomainError::Invariant`] — startup-time failure is loud by
    /// design.
    pub async fn connect(url: &str) -> DomainResult<Self> {
        let config = Config::from_url(url).map_err(|e| map_fred(&e))?;
        let client = Builder::from_config(config)
            .build()
            .map_err(|e| map_fred(&e))?;
        client.init().await.map_err(|e| map_fred(&e))?;
        let on_error_client = client.clone();
        on_error_client.on_error(|(error, server)| async move {
            warn!(
                server = ?server,
                error = %error,
                "redis ephemeral store connection error"
            );
            Ok(())
        });
        debug!(url, "connected to redis for EphemeralStore");
        Ok(Self { client })
    }

    /// Borrow the underlying `fred` client. Only the Redis-specific
    /// integration tests touch this; production code goes through the
    /// `EphemeralStore` port exclusively.
    #[doc(hidden)]
    pub fn client(&self) -> &Client {
        &self.client
    }
}

impl EphemeralStore for RedisEphemeralStore {
    fn get(&self, key: &str) -> BoxFuture<'_, DomainResult<Option<Bytes>>> {
        let client = self.client.clone();
        let key = key.to_owned();
        Box::pin(async move {
            // `hmget` returns an array of Values aligned with the
            // requested field list. A missing key yields Nil for
            // every field; a live key with no `val` field (should
            // never happen given our write shape) also yields Nil.
            let values: Vec<FredValue> = client
                .hmget(key, vec!["val".to_owned()])
                .await
                .map_err(|e| map_fred(&e))?;
            let Some(v) = values.into_iter().next() else {
                return Ok(None);
            };
            match v {
                FredValue::Null => Ok(None),
                FredValue::Bytes(b) => Ok(Some(b)),
                FredValue::String(s) => Ok(Some(Bytes::from(s.to_string()))),
                other => Err(DomainError::Invariant(format!(
                    "ephemeral redis: unexpected HMGET reply shape: {other:?}"
                ))),
            }
        })
    }

    fn put(&self, key: &str, value: Bytes, ttl: Duration) -> BoxFuture<'_, DomainResult<()>> {
        let client = self.client.clone();
        let key = key.to_owned();
        let ttl = ttl_secs(ttl);
        Box::pin(async move {
            let _ver: i64 = client
                .eval(SCRIPT_PUT, vec![key], (value, ttl))
                .await
                .map_err(|e| map_fred(&e))?;
            Ok(())
        })
    }

    fn put_if_absent(
        &self,
        key: &str,
        value: Bytes,
        ttl: Duration,
    ) -> BoxFuture<'_, DomainResult<bool>> {
        let client = self.client.clone();
        let key = key.to_owned();
        let ttl = ttl_secs(ttl);
        Box::pin(async move {
            let created: i64 = client
                .eval(SCRIPT_PUT_IF_ABSENT, vec![key], (value, ttl))
                .await
                .map_err(|e| map_fred(&e))?;
            Ok(created == 1)
        })
    }

    fn compare_and_swap(
        &self,
        key: &str,
        expected_version: u64,
        new_value: Bytes,
        ttl: Duration,
    ) -> BoxFuture<'_, DomainResult<Option<u64>>> {
        let client = self.client.clone();
        let key = key.to_owned();
        let ttl = ttl_secs(ttl);
        // Redis Lua compares via string equality — pass the expected
        // version as its decimal ASCII form so `cur[1] == ARGV[1]`
        // holds for values HSET'd by `SCRIPT_PUT` (which also stores
        // the integer as a Redis bulk string).
        let expected = expected_version.to_string();
        Box::pin(async move {
            let reply: FredValue = client
                .eval(SCRIPT_CAS, vec![key], (expected, new_value, ttl))
                .await
                .map_err(|e| map_fred(&e))?;
            match reply {
                FredValue::Null => Ok(None),
                FredValue::Integer(n) if n >= 0 => Ok(Some(n as u64)),
                other => Err(DomainError::Invariant(format!(
                    "ephemeral redis: unexpected CAS reply shape: {other:?}"
                ))),
            }
        })
    }

    fn delete(&self, key: &str) -> BoxFuture<'_, DomainResult<()>> {
        let client = self.client.clone();
        let key = key.to_owned();
        Box::pin(async move {
            let _: i64 = client.del(key).await.map_err(|e| map_fred(&e))?;
            Ok(())
        })
    }

    fn extend_ttl(&self, key: &str, ttl: Duration) -> BoxFuture<'_, DomainResult<()>> {
        let client = self.client.clone();
        let key = key.to_owned();
        let ttl = ttl_secs(ttl);
        Box::pin(async move {
            // `EXPIRE` on a missing key returns 0 — the port
            // contract pretends that's Ok(()).
            let _: i64 = client
                .expire(key, ttl, None)
                .await
                .map_err(|e| map_fred(&e))?;
            Ok(())
        })
    }

    fn try_increment_counter(
        &self,
        key: &str,
        max: u64,
        ttl: Duration,
    ) -> BoxFuture<'_, DomainResult<Option<u64>>> {
        let client = self.client.clone();
        let key = key.to_owned();
        let ttl = ttl_secs(ttl);
        let max_str = max.to_string();
        Box::pin(async move {
            let reply: FredValue = client
                .eval(SCRIPT_INCREMENT_WITH_CAP, vec![key], (max_str, ttl))
                .await
                .map_err(|e| map_fred(&e))?;
            match reply {
                FredValue::Null => Ok(None),
                FredValue::Integer(n) if n >= 0 => Ok(Some(n as u64)),
                other => Err(DomainError::Invariant(format!(
                    "ephemeral redis: unexpected try_increment_counter reply shape: {other:?}"
                ))),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unit test the `ttl_secs` rounding — no Redis needed, so this
    /// runs in every `cargo test` regardless of the integration
    /// feature gate.
    #[test]
    fn ttl_secs_rounds_up_sub_second_ttls() {
        assert_eq!(ttl_secs(Duration::from_millis(1)), 1);
        assert_eq!(ttl_secs(Duration::from_millis(999)), 1);
        assert_eq!(ttl_secs(Duration::from_millis(1001)), 2);
        assert_eq!(ttl_secs(Duration::from_secs(60)), 60);
    }

    #[test]
    fn ttl_secs_clamps_zero_to_one() {
        assert_eq!(ttl_secs(Duration::ZERO), 1);
    }

    #[test]
    fn map_fred_surfaces_invariant() {
        let e = FredError::new(fred::error::ErrorKind::IO, "boom");
        match map_fred(&e) {
            DomainError::Invariant(msg) => {
                assert!(msg.contains("ephemeral redis failure"));
            }
            other => panic!("expected Invariant, got {other:?}"),
        }
    }
}
