//! READ-SIDE port over the `artifact_groups` + `artifact_group_members`
//! projection.
//!
//! Writes live on `ArtifactGroupLifecyclePort`; the read/write split
//! keeps use cases that only need lookup
//! independent of the transactional-write path.
//!
//! See the refs/groups section of
//! `docs/architecture/explanation/domain-model.md`.
//! The coords-canonicalization contract governing how the
//! `coords_json` JSONB key is built lives on
//! [`ArtifactGroup`](crate::entities::artifact_group::ArtifactGroup).

use uuid::Uuid;

use crate::entities::artifact_group::ArtifactGroup;
use crate::error::DomainResult;
use crate::types::ArtifactCoords;

use super::BoxFuture;

/// READ-SIDE port over the `artifact_groups` + `artifact_group_members`
/// projection.
///
/// No `create` / `add_member` / `remove_member` methods — writes land on
/// `ArtifactGroupLifecyclePort`, so projection
/// updates and event appends commit in the same Postgres transaction.
/// Splitting at the trait level lets use cases that only read depend on
/// this port alone.
pub trait ArtifactGroupRepository: Send + Sync {
    /// Look up one group by canonical coordinates within a repository.
    ///
    /// Returns `None` when no group exists for those coordinates. The
    /// caller is expected to pass coordinates built under the
    /// canonicalization contract documented on
    /// [`ArtifactGroup`](crate::entities::artifact_group::ArtifactGroup) —
    /// passing per-file coords (non-empty `path`, non-null `metadata`)
    /// will miss groups stored under canonicalised coords.
    fn find_by_coords(
        &self,
        repo: Uuid,
        coords: &ArtifactCoords,
    ) -> BoxFuture<'_, DomainResult<Option<ArtifactGroup>>>;

    /// Reverse lookup: "what group does this artifact belong to?"
    ///
    /// An artifact belongs to at most one group. Returns `None` for
    /// single-file artifacts (most PyPI, cargo, RubyGems uploads).
    fn find_by_member(
        &self,
        artifact_id: Uuid,
    ) -> BoxFuture<'_, DomainResult<Option<ArtifactGroup>>>;

    /// Paginated distinct enumeration of group coordinates by primary
    /// role.
    ///
    /// Used by OCI's `_catalog` (`primary_role = "manifest"`); future
    /// format handlers can reuse it (Maven GAV roots, Debian
    /// source-package names) without adding new methods. Returns the
    /// `coords.name` field of each distinct group, byte-stably ordered
    /// under `COLLATE "C"`, strictly greater than `after`. `None` for
    /// `after` means "from the start".
    fn list_distinct_names(
        &self,
        repo: Uuid,
        primary_role: &str,
        after: Option<&str>,
        limit: u32,
    ) -> BoxFuture<'_, DomainResult<Vec<String>>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time assertion that `ArtifactGroupRepository` is
    /// dyn-compatible — the adapter is held as
    /// `Arc<dyn ArtifactGroupRepository>` at composition.
    #[test]
    fn port_is_dyn_compatible() {
        let _ = size_of::<&dyn ArtifactGroupRepository>();
    }
}
