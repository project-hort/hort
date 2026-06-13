//! READ-SIDE port over the `mutable_refs` projection.
//!
//! Writes live on `RefLifecyclePort`; the read/write split keeps use
//! cases that only need lookup
//! independent of the transactional-write path.
//!
//! See the refs/groups section of
//! `docs/architecture/explanation/domain-model.md`.

use uuid::Uuid;

use crate::entities::mutable_ref::{MutableRef, RefTarget};
use crate::error::DomainResult;

use super::BoxFuture;

/// READ-SIDE port over the `mutable_refs` projection.
///
/// No `set` / `delete` methods — writes land on `RefLifecyclePort`,
/// so the projection update and the event append
/// commit in the same Postgres transaction. Splitting at the trait level
/// lets use cases that only read depend on this port alone.
///
/// No `list_all_refs_in_repo` — enumeration without a namespace is
/// unbounded-cardinality on a Docker Hub mirror. The catalog API that
/// needs it paginates by namespace first.
///
/// No pagination on `list` — a single namespace has bounded refs
/// (dozens typical). If a format breaks this, add a paginated variant
/// then; don't speculate now.
pub trait RefRegistryPort: Send + Sync {
    /// Look up one ref by full identity. Returns
    /// `DomainError::NotFound { entity: "MutableRef", .. }` when missing.
    fn find(
        &self,
        repo: Uuid,
        namespace: &str,
        ref_name: &str,
    ) -> BoxFuture<'_, DomainResult<MutableRef>>;

    /// All refs in `(repo, namespace)`. Bounded cardinality (dozens typical).
    fn list(&self, repo: Uuid, namespace: &str) -> BoxFuture<'_, DomainResult<Vec<MutableRef>>>;

    /// Reverse lookup: every ref in `repo` currently pointing at `target`.
    /// Enables operator queries like "which tags resolve to this manifest?"
    /// and "what npm dist-tags point at 1.2.3?". Small cardinality in
    /// practice (few refs per target).
    fn find_by_target(
        &self,
        repo: Uuid,
        target: &RefTarget,
    ) -> BoxFuture<'_, DomainResult<Vec<MutableRef>>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time assertion that `RefRegistryPort` is dyn-compatible —
    /// the adapter is held as `Arc<dyn RefRegistryPort>` at composition.
    #[test]
    fn port_is_dyn_compatible() {
        let _ = size_of::<&dyn RefRegistryPort>();
    }
}
