//! Outbound port for atomic mutable-ref lifecycle transitions.
//!
//! Each call persists both the domain event (`RefMoved` / `RefRetired`) and
//! the mutated `mutable_refs` projection row in a single transaction. The
//! read-side lookup port lives at [`super::ref_registry::RefRegistryPort`];
//! splitting the read and write ports keeps consumers that only lookup
//! independent of the transactional-write path.
//!
//! **Adapter-authoritative idempotence.** Implementations MUST re-read the
//! current target inside the transaction (`SELECT ... FOR UPDATE`) before
//! appending a `RefMoved`. If the current target already equals the new
//! target, the adapter commits without appending an event — the use case's
//! read-then-check is an optimisation; correctness under a concurrent
//! same-target race lives here. The rule: "`from == Some(to)` is not an
//! event".
//!
//! **Concurrent first-placement surfaces as [`RefCommitOutcome::RefAlreadyExists`].**
//! When two callers race on a brand-new `(repo, namespace, ref_name)` with
//! different tentative `ref_id`s, the adapter's `INSERT ... ON CONFLICT
//! (...) DO NOTHING RETURNING id` produces no row on the losing side; the
//! whole transaction rolls back (discarding the loser's `batch` verbatim,
//! mirrors the adapter-never-mutates-payloads rule for groups) and the
//! adapter returns the winner's id. The use case retries by re-reading and
//! dispatching as a move.

use uuid::Uuid;

use crate::entities::mutable_ref::MutableRef;
use crate::error::DomainResult;
use crate::ports::event_store::AppendEvents;

use super::BoxFuture;

/// Outcome of a [`RefLifecyclePort::move_ref`] call. Mirrors the
/// typed-outcome shape used by `ArtifactGroupLifecyclePort` so callers
/// decide whether to retry without parsing error strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefCommitOutcome {
    /// The projection row is at the caller-supplied target and the
    /// `batch` was appended (or omitted if the same-target short-circuit
    /// fired).
    Committed,
    /// A concurrent writer created this ref first. The whole transaction
    /// was rolled back; the loser's `batch` was discarded verbatim. The
    /// caller observes the winner's `existing_id` and retries as a move.
    RefAlreadyExists { existing_id: Uuid },
}

/// Outbound port for atomic mutable-ref write operations.
///
/// The two methods mirror the two lifecycle transitions a ref can undergo:
/// creation/move (`move_ref`) and retirement (`retire_ref`). Both methods
/// wrap the projection-row write and the event append in a single
/// Postgres transaction — neither side can land without the other.
pub trait RefLifecyclePort: Send + Sync {
    /// Atomically persist a ref create-or-move.
    ///
    /// `r` carries the desired post-state (id, repository, namespace, ref
    /// name, new target). The adapter is responsible for:
    ///
    /// 1. Locking the existing row (if any) with `SELECT ... FOR UPDATE`
    ///    inside the transaction.
    /// 2. If the current target equals `r.target`, committing WITHOUT
    ///    appending an event — this is the adapter-authoritative
    ///    idempotence check that defeats a concurrent same-target race.
    /// 3. If no row exists, `INSERT ... ON CONFLICT (repository_id,
    ///    namespace, ref_name) DO NOTHING RETURNING id`. Empty RETURNING
    ///    means a concurrent first-placement won — roll back (discarding
    ///    `batch` verbatim) and return
    ///    [`RefCommitOutcome::RefAlreadyExists`] with the winner's id.
    /// 4. Otherwise UPDATEing the projection row and appending `batch`
    ///    via the event store's in-transaction append helper.
    ///
    /// The `batch` is built by the use case; the adapter does not touch
    /// its event payloads — it only persists what the caller produced.
    fn move_ref(
        &self,
        r: MutableRef,
        batch: AppendEvents,
    ) -> BoxFuture<'_, DomainResult<RefCommitOutcome>>;

    /// Atomically persist a ref retirement.
    ///
    /// Deletes the `mutable_refs` row and appends `batch` (a
    /// `RefRetired` event) in a single transaction. Returns
    /// [`crate::error::DomainError::NotFound`] with
    /// `entity = "MutableRef"` when no row exists for
    /// `(repo, namespace, ref_name)` — the adapter MUST roll back the
    /// transaction in that case and MUST NOT append a `RefRetired`
    /// event for a ref that never existed.
    fn retire_ref(
        &self,
        repo: Uuid,
        namespace: &str,
        ref_name: &str,
        batch: AppendEvents,
    ) -> BoxFuture<'_, DomainResult<()>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time assertion that `RefLifecyclePort` is dyn-compatible —
    /// the adapter is held as `Arc<dyn RefLifecyclePort>` at composition.
    #[test]
    fn port_is_dyn_compatible() {
        // Compile-time: resolves only if the trait is dyn-compatible.
        // Runtime: size_of call executes in the test body for coverage.
        let _ = size_of::<&dyn RefLifecyclePort>();
    }
}
