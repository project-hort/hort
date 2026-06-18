//! Outbound port for atomic artifact-group lifecycle transitions.
//!
//! Each call persists both the domain events (`ArtifactGroupInitiated`,
//! `ArtifactGroupMemberAdded`, `ArtifactGroupMemberRemoved`,
//! `ArtifactGroupPrimaryRoleAssigned`) and the mutated
//! `artifact_groups` + `artifact_group_members` projection rows in a
//! single transaction. The read-side lookup port lives at
//! [`super::artifact_group_repository::ArtifactGroupRepository`]; the
//! read/write split keeps consumers that only lookup independent of the
//! transactional-write path.
//!
//! # Three load-bearing rules — do not deviate
//!
//! 1. **The adapter MUST NEVER mutate or re-serialise `DomainEvent`
//!    payloads.** The caller builds an [`AppendEvents`] and the adapter
//!    either appends it verbatim under a committed transaction, or rolls
//!    back and surfaces the observed state. Pattern-matching on
//!    `DomainEvent::ArtifactGroup*` variants to "patch" an embedded
//!    `group_id` couples the adapter to every event variant's shape and
//!    turns the write path into a maintenance trap.
//! 2. **The concurrent-create race surfaces as a typed outcome.** When
//!    two callers simultaneously `INSERT INTO artifact_groups ...
//!    ON CONFLICT (repository_id, coords_json) DO NOTHING RETURNING id`,
//!    the loser observes an empty `RETURNING`, looks up the winner's id
//!    with a `SELECT`, rolls the transaction back entirely, and returns
//!    [`GroupCommitOutcome::GroupAlreadyExists { existing_id }`] without
//!    appending any events. The caller (the use case) retries with the
//!    observed id, rebuilding fresh events — never patching the prior
//!    batch.
//! 3. **The primary-role-assignment race is an unrecoverable conflict,
//!    not a retry.** When `GroupMemberCommit::primary_role_assigned` is
//!    `Some(_)` and two callers race to fix the same group's
//!    `primary_role`, exactly one of them wins the conditional `UPDATE
//!    ... WHERE primary_role = ''`. The loser's entire transaction —
//!    including the member-add — is rolled back and the adapter returns
//!    [`crate::error::DomainError::Conflict`]. Member-add for the losing
//!    call does NOT land. The caller has to re-fetch and make a
//!    different decision (retry with `is_primary = false`).

use uuid::Uuid;

use crate::entities::artifact_group::{ArtifactGroup, ArtifactGroupMember};
use crate::error::DomainResult;
use crate::ports::event_store::AppendEvents;

use super::BoxFuture;

// ---------------------------------------------------------------------------
// GroupMemberCommit
// ---------------------------------------------------------------------------

/// The write intent handed to [`ArtifactGroupLifecyclePort::commit_member_added`].
///
/// Three fields pack the three decisions the use case made before
/// delegating to the adapter:
///
/// - `new_group = Some(..)` — the use case believes this call is the
///   first placement for `(repository_id, coords)`. The adapter
///   `INSERT ... ON CONFLICT DO NOTHING` may still find that another
///   concurrent caller won, in which case the adapter returns
///   [`GroupCommitOutcome::GroupAlreadyExists { existing_id }`] and the
///   use case retries with `new_group = None` against `existing_id`.
///
/// - `new_group = None` — the use case already resolved the group
///   (either by a fresh `find_by_coords` lookup or by observing the
///   winner's id on a retry). The adapter skips the group INSERT and
///   proceeds straight to the member INSERT.
///
/// - `primary_role_assigned = Some(role)` — the use case decided this
///   add should also fix the group's `primary_role` (the primary-role-assignment case:
///   group was created without a primary and this member arrives with
///   `is_primary = true`). The adapter runs a race-safe
///   `UPDATE ... WHERE primary_role = ''`. A concurrent caller that
///   already set the slot is a [`crate::error::DomainError::Conflict`],
///   not a retry.
pub struct GroupMemberCommit {
    /// `Some(group)` when this call is expected to create the group.
    /// `None` when adding to an existing group (retry path or later
    /// member join).
    pub new_group: Option<ArtifactGroup>,
    /// The member to add. Always present.
    pub member: ArtifactGroupMember,
    /// `Some(role)` when this add also fixes a previously-empty
    /// `primary_role`. See the primary-role-assignment case.
    pub primary_role_assigned: Option<String>,
}

// ---------------------------------------------------------------------------
// GroupCommitOutcome
// ---------------------------------------------------------------------------

/// The typed result of [`ArtifactGroupLifecyclePort::commit_member_added`].
///
/// Separating `Committed` from `GroupAlreadyExists` lets the use case
/// own the bounded-retry loop without the adapter ever having to
/// rewrite caller-owned `DomainEvent` payloads. The alternative — an
/// adapter that re-serialises the event batch to patch a stale
/// `group_id` — was rejected by design because it couples the adapter
/// to every event variant's JSON shape.
#[derive(Debug)]
pub enum GroupCommitOutcome {
    /// Projection rows + events committed atomically.
    Committed,
    /// A concurrent writer created the group first. The adapter rolled
    /// back the entire transaction (no member row, no events); the
    /// caller MUST re-invoke with fresh events built against
    /// `existing_id`.
    GroupAlreadyExists { existing_id: Uuid },
}

// ---------------------------------------------------------------------------
// ArtifactGroupLifecyclePort
// ---------------------------------------------------------------------------

/// Outbound port for atomic artifact-group write operations.
///
/// Two methods, one per lifecycle transition of a group member:
/// creation/attach (`commit_member_added`) and detach
/// (`commit_member_removed`). Both wrap the projection-row write and
/// the event append in a single Postgres transaction — neither side
/// can land without the other.
pub trait ArtifactGroupLifecyclePort: Send + Sync {
    /// Atomically attach a member to a group (creating the group if
    /// `change.new_group.is_some()`), optionally assigning the primary
    /// role (the primary-role-assignment case), and append the caller-supplied events.
    ///
    /// # Adapter contract
    ///
    /// 1. Begin a transaction.
    /// 2. When `change.new_group.is_some()`, `INSERT ... ON CONFLICT
    ///    (repository_id, coords_json) DO NOTHING RETURNING id`. On
    ///    empty return, `SELECT id ... WHERE repository_id = $1 AND
    ///    coords_json = $2`, roll back the transaction entirely, and
    ///    return [`GroupCommitOutcome::GroupAlreadyExists`].
    /// 3. When `change.primary_role_assigned.is_some()`,
    ///    `UPDATE artifact_groups SET primary_role = $1 WHERE id = $2
    ///    AND primary_role = ''`. Zero rows affected → roll back and
    ///    return [`crate::error::DomainError::Conflict`].
    /// 4. `INSERT INTO artifact_group_members ... ON CONFLICT
    ///    (group_id, artifact_id) DO NOTHING`. On 0-row conflict,
    ///    inspect the existing row's role:
    ///    - same role → idempotent no-op, do NOT append events, return
    ///      `Ok(Committed)`.
    ///    - different role → roll back and return `Conflict`.
    /// 5. Otherwise append `batch` verbatim via the event store's
    ///    in-transaction helper, commit, and return `Ok(Committed)`.
    ///
    /// The adapter MUST NOT touch `batch.events` — the caller owns the
    /// payloads and the adapter is a pass-through.
    fn commit_member_added(
        &self,
        change: GroupMemberCommit,
        batch: AppendEvents,
    ) -> BoxFuture<'_, DomainResult<GroupCommitOutcome>>;

    /// Atomically detach a member from a group and append the
    /// `ArtifactGroupMemberRemoved` event.
    ///
    /// `DELETE FROM artifact_group_members WHERE group_id = $1 AND
    /// artifact_id = $2 RETURNING role`. Zero rows → `NotFound`,
    /// transaction rolled back, no event appended.
    fn commit_member_removed(
        &self,
        group_id: Uuid,
        artifact_id: Uuid,
        batch: AppendEvents,
    ) -> BoxFuture<'_, DomainResult<()>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time assertion that `ArtifactGroupLifecyclePort` is
    /// dyn-compatible — the adapter is held as
    /// `Arc<dyn ArtifactGroupLifecyclePort>` at composition.
    #[test]
    fn port_is_dyn_compatible() {
        let _ = size_of::<&dyn ArtifactGroupLifecyclePort>();
    }

    /// Exhaustively match every [`GroupCommitOutcome`] variant so a
    /// future addition is caught by the compiler. Construction is
    /// trivial — these are domain-layer types with `pub` fields.
    #[test]
    fn group_commit_outcome_variants_match_exhaustively() {
        let committed = GroupCommitOutcome::Committed;
        let exists = GroupCommitOutcome::GroupAlreadyExists {
            existing_id: Uuid::new_v4(),
        };
        for outcome in [committed, exists] {
            match outcome {
                GroupCommitOutcome::Committed => {}
                GroupCommitOutcome::GroupAlreadyExists { existing_id: _ } => {}
            }
        }
    }
}
