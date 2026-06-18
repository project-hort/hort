//! Outbound port for the `policy_projections` table.
//!
//! The projection is the materialised current state derived from the
//! per-policy event stream (`StreamCategory::Policy`). It exists so
//! `find_by_name` and `list_exclusions_for_policy` are O(1) reads
//! against an indexed table rather than full stream replays.
//!
//! ## Write contract
//!
//! `PolicyUseCase` calls `upsert` immediately after each successful event
//! append, in the same DB transaction as the event-store
//! `append_to_stream` call. `stream_version` on the supplied projection is
//! the post-append `AppendResult.stream_position` — that field then drives
//! [`ExpectedVersion::Exact`](crate::ports::event_store::ExpectedVersion::Exact)
//! on the next mutation. A concurrent imperative-API write between
//! projection-read and event-append fails the apply with a clear
//! `ConcurrentModification` error.
//!
//! Out-of-band rebuild from the event log is a future operational
//! tool; this port only serves the synchronous-after-append path.

use uuid::Uuid;

use crate::entities::scan_policy::{ExclusionProjection, ScanPolicyProjection};
use crate::error::DomainResult;

use super::BoxFuture;

/// Outbound port for the `policy_projections` + `exclusion_projections`
/// tables. All writes are gitops-authored via `PolicyUseCase`; there
/// is no imperative HTTP API.
pub trait PolicyProjectionRepository: Send + Sync {
    /// Look up a policy by its UUID. Returns `Ok(None)` when no row
    /// exists; archived rows are returned as `Some` so callers can
    /// distinguish "never existed" from "tombstoned".
    fn find_by_id(&self, id: Uuid) -> BoxFuture<'_, DomainResult<Option<ScanPolicyProjection>>>;

    /// Look up an active (non-archived) policy by its YAML
    /// `metadata.name`. Backed by the partial index
    /// `idx_policy_projections_active_name` (`005_policy.sql`) so
    /// archived rows do not collide with a re-created policy of the
    /// same name.
    fn find_by_name(&self, name: &str)
        -> BoxFuture<'_, DomainResult<Option<ScanPolicyProjection>>>;

    /// Look up a policy by its YAML `metadata.name`, including
    /// archived rows. Used exclusively by the gitops apply pipeline's
    /// reactivation path: when the desired YAML re-declares a policy
    /// whose only matching projection is archived, the apply emits
    /// [`PolicyReactivated`](crate::events::PolicyReactivated) on the
    /// existing stream rather than minting a new `policy_id` (which
    /// would collide with the archived row's UNIQUE-name constraint
    /// in `policy_projections`).
    ///
    /// `Some` is returned for both active and archived rows; the
    /// caller inspects [`ScanPolicyProjection::archived`] to decide
    /// the branch. `None` means no row exists for this name in any
    /// state. Other call sites should keep using
    /// [`find_by_name`](Self::find_by_name) — the apply pipeline is
    /// the only place where seeing archived rows is the right
    /// behaviour.
    fn find_by_name_including_archived(
        &self,
        name: &str,
    ) -> BoxFuture<'_, DomainResult<Option<ScanPolicyProjection>>>;

    /// Every active (non-archived) policy. Used by 14b's diff to
    /// determine which projected policies are absent from the
    /// desired YAML and therefore need a `PolicyArchived` event.
    fn list_active(&self) -> BoxFuture<'_, DomainResult<Vec<ScanPolicyProjection>>>;

    /// Every exclusion currently attached to the given policy.
    /// Backed by the partial index
    /// `idx_exclusion_projections_policy_id` (`005_policy.sql`) for
    /// O(log n) lookup. Order is implementation-defined; callers
    /// must not depend on a specific ordering.
    fn list_exclusions_for_policy(
        &self,
        policy_id: Uuid,
    ) -> BoxFuture<'_, DomainResult<Vec<ExclusionProjection>>>;

    /// INSERT-or-UPDATE the projection row in lockstep with the
    /// event-store append. `stream_version` on the supplied
    /// projection is the post-append `AppendResult.stream_position`
    /// — the use case writes both in the same DB transaction.
    fn upsert(&self, projection: &ScanPolicyProjection) -> BoxFuture<'_, DomainResult<()>>;

    /// INSERT-or-UPDATE one exclusion row. Identity is `exclusion_id`
    /// (mirrors `ExclusionAdded.exclusion_id`).
    fn upsert_exclusion(&self, exclusion: &ExclusionProjection) -> BoxFuture<'_, DomainResult<()>>;

    /// Remove one exclusion row. The event-stream record of the
    /// removal lives on the parent policy stream; this only drops
    /// the materialised view.
    fn delete_exclusion(&self, exclusion_id: Uuid) -> BoxFuture<'_, DomainResult<()>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time dyn-compatibility assertion. The function is
    /// never invoked; its existence forces the compiler to verify
    /// `PolicyProjectionRepository` is dyn-compatible. If a future
    /// edit adds a generic parameter or `-> impl Trait` method it
    /// fails here, not at the use-case call site.
    fn _assert_dyn_compatible(_: Box<dyn PolicyProjectionRepository>) {}

    /// Runtime stub that exercises the dyn-compatibility assertion
    /// for coverage. The size_of call resolves only if the trait is
    /// dyn-compatible.
    #[test]
    fn port_is_dyn_compatible() {
        let _ = size_of::<&dyn PolicyProjectionRepository>();
    }
}
