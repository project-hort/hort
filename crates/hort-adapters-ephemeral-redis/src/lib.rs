//! Redis adapter for the `EphemeralStore` port, built on the `fred`
//! client. The port contract is documented in
//! `docs/architecture/explanation/` and enforced by the
//! `ephemeral_keyspace_exhaustive` guard test.
//!
//! Every port method maps to one or two Redis commands:
//!
//! - `put` / `put_if_absent` / `compare_and_swap` → a Lua `EVAL` that
//!   atomically reads the existing version, decides, writes, and
//!   sets the TTL.
//! - `get` → `HMGET key v val` (we ignore `v`; CAS is the only
//!   caller that needs the version).
//! - `delete` → `DEL`.
//! - `extend_ttl` → `EXPIRE`; missing keys are an `Ok(())` no-op per
//!   the port contract.
//!
//! Values are stored in a Redis hash at `key` with two fields:
//! `v` (the version counter as an ASCII integer) and `val` (the raw
//! bytes).

mod metrics;
mod store;

pub use metrics::MeteredEphemeralStore;
pub use store::RedisEphemeralStore;
