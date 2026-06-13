//! Shared inbound-HTTP primitives for hort.
//!
//! Hosts the pieces every per-format HTTP crate (`hort-http-cargo`,
//! `hort-http-npm`, `hort-http-pypi`, `hort-http-oci`) consumes: the
//! [`AppContext`](context::AppContext) struct, the middleware stack, authz
//! extractors, [`ApiError`](error::ApiError), and the admin and metrics
//! handlers plus the router wrapper that applies the full middleware chain.
//!
//! Adapter-free by construction. `Cargo.toml` lists no `hort-adapters-*`
//! crate (and no `sqlx` / `reqwest`) so `use hort_adapters_postgres::…`
//! inside this crate is an unresolved-import compile error — the
//! hexagonal boundary is enforced by the dep graph, not by review
//! (ADR 0008).

pub mod authz;
pub mod body;
/// Generic pull-through projection-cache envelope shared by the
/// npm / cargo / pypi proxy caches (dedupes the three byte-identical
/// per-format `Cached*Projection` structs). See the module docs.
pub mod cache_envelope;
pub mod context;
pub mod error;
pub mod handlers;
pub mod limits;
pub mod middleware;
pub mod router;
pub mod url_resolver;

/// Shared mock [`context::AppContext`] construction for router + handler
/// tests across the inbound-HTTP crates. See module docs.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
