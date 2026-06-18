//! Outbound port for invalidating cached upstream-index entries on
//! `ArtifactRejected`.
//!
//! # What this is
//!
//! When an artifact transitions to `Rejected` (curator-block,
//! fail-closed scan rejection, or retroactive curation-rule rejection),
//! the upstream packument / simple-index / sparse-index cache continues
//! to advertise the now-revoked artifact until the entry's TTL elapses.
//! For a curator-blocked wheel, a pip-compile-style
//! metadata-only client could still reach the `.metadata` via the
//! cached simple-index advertisement during that window.
//!
//! This port lets the application layer invalidate the per-`(repository,
//! package)` cache rows across every upstream mapping configured on the
//! repository, on every `ArtifactRejected` emission.
//!
//! # Best-effort, not load-bearing
//!
//! A returned `Err` does **NOT** roll back the caller's event-store
//! append. The `NonServableStatusFilter` (see
//! `docs/architecture/explanation/index-construction.md`) on the next
//! index-build is the load-bearing close on the index-build path; this port
//! is defense-in-depth cache hygiene that shortens the freshness-of-
//! revocation-signal window from `TTL` to "immediate OR next index
//! build, whichever fires first".
//!
//! # Port-shape rationale
//!
//! Shares the `Send + Sync` + `&self` + dyn-compatible shape of
//! [`ApiTokenCacheInvalidator`](crate::ports::api_token_cache_invalidator)
//! — but **diverges on async**:
//! `ApiTokenCacheInvalidator`'s methods are synchronous because
//! `PatCache` is in-process (`Mutex`-only, no I/O); this port returns
//! `BoxFuture<'_, DomainResult<u32>>` because the impl reads
//! `RepositoryRepository` (DB) and `EphemeralStore` (Redis-backed) on
//! every call. The async return shape follows every other domain port
//! in the workspace ([`StoragePort`](crate::ports::storage),
//! [`ArtifactRepository`](crate::ports::artifact_repository),
//! [`EventStore`](crate::ports::event_store)).
//!
//! `package_raw_name: &str` and not `ArtifactCoords` — the cache is
//! keyed on the *upstream-visible* name (npm packument keys on raw
//! name; PyPI on the PEP 503 normalised name; cargo on the lowercased
//! sparse-index path). The implementation normalises per-format.
//! Passing `ArtifactCoords` would force the domain layer to know which
//! field carries the cache-relevant identifier, leaking format-handler
//! concerns into the port boundary.

use uuid::Uuid;

use crate::error::DomainResult;
use crate::ports::BoxFuture;

/// Outbound port for invalidating cached upstream index entries
/// (npm packument, PyPI simple-index, cargo per-crate sparse-index)
/// when an artifact transitions to `Rejected`. See module-level docs
/// for semantics; see the authoritative spec for the per-format cache
/// key shapes and emission-site wiring.
pub trait UpstreamIndexCacheInvalidator: Send + Sync {
    /// Drop every cached upstream-index entry for `(repository_id,
    /// package_raw_name)` across every upstream mapping configured on
    /// the repository. Returns the count of keys evicted (for the
    /// debug-log line; not load-bearing).
    ///
    /// Failure is best-effort: a returned `Err` does NOT roll back the
    /// caller's event-store append. The caller logs `tracing::warn!`
    /// and continues; the `NonServableStatusFilter` on the next index
    /// build is the load-bearing close.
    fn invalidate_for_package(
        &self,
        repository_id: Uuid,
        package_raw_name: &str,
    ) -> BoxFuture<'_, DomainResult<u32>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time + runtime assertion that
    /// [`UpstreamIndexCacheInvalidator`] is dyn-compatible. The
    /// composition root wires it behind `Arc<dyn
    /// UpstreamIndexCacheInvalidator>`; a non-dyn-compatible signature
    /// would break that wiring at compile time. The runtime `size_of`
    /// call exercises the assertion in the test body so coverage
    /// tooling counts it. Mirrors `ApiTokenCacheInvalidator`'s pattern.
    #[test]
    fn _assert_dyn_compat() {
        let _ = size_of::<&dyn UpstreamIndexCacheInvalidator>();
    }
}
