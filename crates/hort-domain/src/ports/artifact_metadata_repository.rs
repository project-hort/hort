use std::collections::HashMap;

use uuid::Uuid;

use crate::entities::artifact::ArtifactMetadata;
use crate::error::DomainResult;

use super::BoxFuture;

/// Outbound port for the `ArtifactMetadata` projection (read-only).
///
/// Writes are deliberately absent from this trait. The atomic event +
/// artifact + metadata write path lives on
/// [`ArtifactLifecyclePort::commit_transition`](super::artifact_lifecycle::ArtifactLifecyclePort::commit_transition),
/// which accepts an optional [`ArtifactMetadata`]. Keeping write discipline
/// on one port prevents dual-write hazards where events, the artifact row,
/// and the metadata row could diverge under crash or transaction-isolation
/// failure.
///
/// The Postgres adapter exposes a non-trait `upsert_in_tx` inherent method
/// that `PgArtifactLifecycle` calls inside the lifecycle transaction —
/// that's the only write path.
pub trait ArtifactMetadataRepository: Send + Sync {
    /// Fetch metadata for a single artifact. Returns `Ok(None)` if the
    /// artifact has no metadata row yet (not every ingest populates one —
    /// proxied fetches with an unreadable body skip the write).
    fn find_by_artifact_id(
        &self,
        artifact_id: Uuid,
    ) -> BoxFuture<'_, DomainResult<Option<ArtifactMetadata>>>;

    /// Fetch metadata for a batch of artifacts in a single query. Missing
    /// ids are simply absent from the returned map — the caller decides
    /// how to handle the gap.
    fn list_by_artifact_ids(
        &self,
        ids: &[Uuid],
    ) -> BoxFuture<'_, DomainResult<HashMap<Uuid, ArtifactMetadata>>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time assertion that `ArtifactMetadataRepository` is dyn-compatible.
    #[test]
    fn port_is_dyn_compatible() {
        // Compile-time: resolves only if the trait is dyn-compatible.
        // Runtime: size_of call executes in the test body for coverage.
        let _ = size_of::<&dyn ArtifactMetadataRepository>();
    }
}
