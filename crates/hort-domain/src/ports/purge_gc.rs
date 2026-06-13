//! Outbound port the **storage-GC walk**
//! (`PurgeUseCase::process_expired`) uses: read
//! the pending-purge work set and, in one committed idempotent
//! transaction, decrement the `content_references` projection and
//! report the post-delete cross-`kind` remaining count per CAS hash.
//!
//! # Why this exists
//!
//! Item B3 (`RetentionUseCase::evaluate_policies`) is stage one of the
//! two-stage retention split — it appends an
//! [`ArtifactExpired`](crate::events::ArtifactExpired) to the artifact
//! stream and deletes nothing. Item B4 is stage two: for every
//! `ArtifactExpired` with no following
//! [`ArtifactPurged`](crate::events::ArtifactPurged) it runs the §5
//! algorithm (decrement `content_references`, delete the CAS blob iff
//! the cross-`kind` refcount hit `0`, append `ArtifactPurged`). The
//! `hort-app` `PurgeUseCase` is pure orchestration over this port plus
//! the existing [`StoragePort`](super::storage::StoragePort) and the
//! event store; the §5 SQL (lock + `DELETE … RETURNING` + cross-`kind`
//! count) lives in the Postgres adapter.
//!
//! # Why a *new, separate* additive port (not extra methods on
//! [`ContentReferenceIndex`](super::content_reference_index::ContentReferenceIndex))
//!
//! Identical reasoning to the B3.5
//! [`RefcountReconcilePort`](super::refcount_reconcile::RefcountReconcilePort)
//! split (B4's literal hard prerequisite and structural sibling). The
//! B4 scope contract forbids changing any existing port/trait
//! signature; `ContentReferenceIndex` already ships with `insert` /
//! `find_by_target` / `delete_by_source` plus several impls and mocks.
//! Adding the transactional GC-walk surface to *that* trait would
//! mutate an existing port signature. So the GC-walk surface is a
//! **distinct, purely-additive** trait — zero existing impls touched.
//! It reuses the shipped [`ContentHash`](crate::types::ContentHash)
//! type so nothing is redefined.
//!
//! # Why the port returns refcount *decisions* (data), not a "purge" verb
//!
//! Keeping the transactional decrement and the storage delete /
//! `ArtifactPurged` append as separate concerns that exchange typed
//! decision data lets the `hort-app` `PurgeUseCase` stay pure
//! orchestration (100% mock-testable per the `hort-app` coverage tier —
//! the §6-invariant-1 re-assertion, the two-stage idempotency split,
//! the `info!`/`warn!`/`error!` policy, the summary) while the SQL
//! (row lock, set-based `DELETE … RETURNING`, cross-`kind` count)
//! stays in the Postgres adapter (≥85% integration-tested). The use
//! case never embeds SQL; the adapter never embeds the
//! tracing/summary/idempotency-orchestration policy.

use uuid::Uuid;

use crate::entities::artifact::QuarantineStatus;
use crate::error::DomainResult;
use crate::types::ContentHash;

use super::BoxFuture;

/// One artifact with a pending `ArtifactExpired` (no following
/// `ArtifactPurged`) the §5 GC walk must process. Carries the
/// quarantine status so the use case can re-assert §6 invariant 1
/// (defence-in-depth) before any destructive step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPurge {
    /// The artifact whose `ArtifactExpired` is pending purge. Also the
    /// `entity_id` of its artifact stream.
    pub artifact_id: Uuid,
    /// Status as projected at scan time — used only to re-assert §6
    /// invariant 1 (the adapter already excludes the protected states;
    /// this is the conservative second check a destructive item owes).
    pub quarantine_status: QuarantineStatus,
}

/// One refcount decision the adapter's transactional §5 step 2+3
/// produced for a single CAS hash referenced by the purged artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgedRef {
    /// The CAS content hash whose `content_references` row(s) for this
    /// artifact were removed. Recoverable from
    /// `artifacts.checksum_sha256` / `artifact_metadata.metadata_blob`
    /// even on an idempotent retry where the projection rows were
    /// already gone.
    pub content_hash: ContentHash,
    /// Cross-`kind` `content_references` count for `content_hash`
    /// **after** this artifact's references were removed (§5 step 3).
    /// `0` ⇒ the blob is GC-eligible and must be deleted; `> 0` ⇒ a
    /// live reference keeps the blob and only this ref is gone.
    pub refs_remaining: u32,
}

/// Read + transactional-decrement outbound port for the
/// storage-GC walk. Purely additive — introduces no change to any
/// existing port. The Postgres adapter implements the SQL (lock +
/// `DELETE … RETURNING` + cross-`kind` count) in one committed,
/// idempotent transaction; unit tests use an in-memory mock.
pub trait PurgeGcPort: Send + Sync {
    /// Every artifact with an `ArtifactExpired` event and **no**
    /// following `ArtifactPurged` — the §5 "pending purge" work set.
    /// MUST exclude `quarantine_status ∈ {quarantined, rejected,
    /// scan_indeterminate}` (§6 invariant 1); the use case re-asserts
    /// this regardless (defence-in-depth).
    fn list_pending_purge(&self) -> BoxFuture<'_, DomainResult<Vec<PendingPurge>>>;

    /// §5 steps 1–3 in **one committed, idempotent transaction**:
    /// lock the artifact row `FOR UPDATE`, `DELETE` the
    /// `primary_content` + `metadata_blob` `content_references` rows,
    /// and return one [`PurgedRef`] per distinct hash with the
    /// post-delete cross-`kind` remaining count.
    ///
    /// **Idempotent**: if a prior partial run already deleted the
    /// rows, the adapter recovers the hash(es) from the authoritative
    /// `artifacts.checksum_sha256` / `artifact_metadata.metadata_blob`
    /// columns and recomputes the (now stable) remaining count, so a
    /// retry still yields the decisions needed to finish the purge.
    /// The storage delete + `ArtifactPurged` append happen **after**
    /// this returns (different ports); on their failure the next sweep
    /// re-invokes this and the recoverable-hash property keeps the
    /// retry correct (two-stage idempotency).
    fn purge_artifact_refs(&self, artifact_id: Uuid)
        -> BoxFuture<'_, DomainResult<Vec<PurgedRef>>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH_A: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn hash(s: &str) -> ContentHash {
        s.parse().unwrap()
    }

    /// Compile-time dyn-compatibility assertion (mirrors the pattern in
    /// [`crate::ports::refcount_reconcile`]).
    #[test]
    fn purge_gc_port_is_dyn_compatible() {
        let _ = size_of::<&dyn PurgeGcPort>();
    }

    /// A no-op impl proves the trait can be `dyn`-cast and stands in
    /// for adapter impls in cross-crate tests.
    struct EmptyPort;
    impl PurgeGcPort for EmptyPort {
        fn list_pending_purge(&self) -> BoxFuture<'_, DomainResult<Vec<PendingPurge>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn purge_artifact_refs(
            &self,
            _artifact_id: Uuid,
        ) -> BoxFuture<'_, DomainResult<Vec<PurgedRef>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    #[tokio::test]
    async fn empty_port_returns_no_pending_and_no_refs() {
        let p = EmptyPort;
        assert!(p.list_pending_purge().await.unwrap().is_empty());
        assert!(p.purge_artifact_refs(Uuid::nil()).await.unwrap().is_empty());
    }

    /// `DomainError` round-trips through every return signature — the
    /// adapter surfaces SQL failures this way and the use case maps
    /// them to `AppError::Domain`.
    #[tokio::test]
    async fn errors_round_trip_through_port_signatures() {
        use crate::error::DomainError;
        struct ErrPort;
        impl PurgeGcPort for ErrPort {
            fn list_pending_purge(&self) -> BoxFuture<'_, DomainResult<Vec<PendingPurge>>> {
                Box::pin(async { Err(DomainError::Invariant("pending list failed".into())) })
            }
            fn purge_artifact_refs(
                &self,
                _artifact_id: Uuid,
            ) -> BoxFuture<'_, DomainResult<Vec<PurgedRef>>> {
                Box::pin(async { Err(DomainError::Invariant("purge tx failed".into())) })
            }
        }
        let p = ErrPort;
        assert!(matches!(
            p.list_pending_purge().await.unwrap_err(),
            DomainError::Invariant(_)
        ));
        assert!(matches!(
            p.purge_artifact_refs(Uuid::nil()).await.unwrap_err(),
            DomainError::Invariant(_)
        ));
    }

    /// The data types are plain value structs — round-trip equality +
    /// the `quarantine_status` field carries through (used by the
    /// use-case §6-invariant-1 re-assertion).
    #[test]
    fn data_types_round_trip() {
        let a = Uuid::new_v4();
        let pp = PendingPurge {
            artifact_id: a,
            quarantine_status: QuarantineStatus::Released,
        };
        assert_eq!(pp.clone(), pp);
        assert_eq!(pp.artifact_id, a);
        assert_eq!(pp.quarantine_status, QuarantineStatus::Released);

        let pr = PurgedRef {
            content_hash: hash(HASH_A),
            refs_remaining: 0,
        };
        assert_eq!(pr.clone(), pr);
        assert_eq!(pr.content_hash.as_ref(), HASH_A);
        assert_eq!(pr.refs_remaining, 0);
    }
}
