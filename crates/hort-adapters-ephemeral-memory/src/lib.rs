//! In-memory `EphemeralStore` adapter.
//!
//! Stores entries in a `DashMap<String, MemEntry>` with per-key
//! `tokio::sync::Mutex` locks for CAS, and spawns a 1-second eviction
//! sweep task on construction. Suitable for single-node / test /
//! dev-loop use; production multi-node deployments use the Redis
//! adapter (`hort-adapters-ephemeral-redis`) so every replica sees the
//! same upload-session state.
//!
//! See `hort_domain::ports::ephemeral_store::EphemeralStore` for the
//! port contract this adapter implements.

mod metrics;
mod store;

pub use metrics::MeteredEphemeralStore;
pub use store::InMemoryEphemeralStore;
