//! Upstream resolver port.
//!
//! Synchronous longest-prefix-match resolution from a per-repository
//! mapping table to the upstream that should serve a given requested
//! name. Format-agnostic by design — OCI is the first consumer (multi-
//! upstream pull-through mirroring) but the trait does not encode any
//! OCI semantics.
//!
//! # Why a port and not a concrete type
//!
//! The resolver implementation lives in `hort-http-oci` (an inbound
//! adapter), but consumers reach it via `Arc<dyn UpstreamResolver>` on
//! [`crate::ports`-adjacent] `AppContext`. Keeping the trait in
//! `hort-domain` means:
//!
//! 1. The format-agnostic property of `AppContext` survives (no
//!    `Arc<CachingResolver>` directly on the field).
//! 2. Tests can substitute a static-table mock without going through
//!    the live cache-refresh task.
//! 3. Future format-specific resolvers (e.g. an npm scope-aware
//!    resolver) can implement the same port and ship in their own
//!    inbound crate without touching `AppContext`'s field type.
//!
//! # Why synchronous
//!
//! `resolve()` is called per-request on the OCI pull-through path and
//! must return in microseconds. The implementation reads through an
//! `ArcSwap`-backed in-memory cache; no I/O, no `await` — synchronous
//! is the right surface. The cache is refreshed by a background task
//! (wired in `hort-server`), not by the request path.
//!
//! # Strip semantics
//!
//! The returned tuple's second component is the requested name with
//! the matched `path_prefix` stripped. For OCI multi-upstream
//! routing:
//!
//! - Request: `dockerhub/library/nginx`
//! - Mapping: `path_prefix = "dockerhub/"`
//! - Result: `(mapping, "library/nginx")`
//!
//! The resolver is also responsible for upstream-specific
//! normalization (today: Docker Hub single-name `library/` rewrite
//! gated on the upstream URL host). Single-upstream
//! mappings (`path_prefix = ""`) pass the requested name through
//! unchanged.
//!
//! See `docs/architecture/how-to/oci-pull-through.md`.

use uuid::Uuid;

use crate::ports::repository_upstream_mapping_repository::RepositoryUpstreamMapping;

/// Outbound port: resolve a per-repository upstream + name pair from
/// a requested name.
///
/// `resolve` returns:
/// - `Some((mapping, stripped_name))` when a matching mapping exists
///   for `repo_id` whose `path_prefix` is a prefix of
///   `requested_name`. The longest matching prefix wins.
/// - `None` when no mapping matches (the repository has no upstreams,
///   or none of them prefix the requested name).
pub trait UpstreamResolver: Send + Sync {
    fn resolve(
        &self,
        repo_id: Uuid,
        requested_name: &str,
    ) -> Option<(RepositoryUpstreamMapping, String)>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time assertion that the port is dyn-compatible — held
    /// as `Arc<dyn UpstreamResolver>` on `AppContext`.
    #[test]
    fn port_is_dyn_compatible() {
        let _ = size_of::<&dyn UpstreamResolver>();
    }
}
