//! Outbound port the **storage-GC walk**
//! (`PurgeUseCase::process_expired`) uses: read
//! the pending-purge work set and, in one committed idempotent
//! transaction, decrement the `content_references` projection and
//! persist and report the post-delete cross-`kind` remaining count per
//! CAS hash. Storage completion is checkpointed per hash; only after
//! every checkpoint exists may the adapter atomically append all
//! terminal events and retire the artifact projection.
//!
//! # Why this exists
//!
//! `RetentionUseCase::evaluate_policies` is stage one of the two-stage
//! retention split — it appends an
//! [`ArtifactExpired`](crate::events::ArtifactExpired) to the artifact
//! stream and deletes nothing. `PurgeUseCase` is stage two: for every
//! **byte-release work item** with no following
//! [`ArtifactPurged`](crate::events::ArtifactPurged) it runs the
//! decrement-and-GC algorithm (decrement `content_references`, delete the
//! CAS blob iff the cross-`kind` refcount hit `0`, append every
//! `ArtifactPurged`, and retire the projection).
//! The `hort-app` `PurgeUseCase` is pure orchestration over this port plus
//! the existing [`StoragePort`](super::storage::StoragePort) and the event
//! store; the SQL (lock + `DELETE … RETURNING` + cross-`kind` count) lives
//! in the Postgres adapter.
//!
//! # Two work items, one collector
//!
//! A byte-release work item is an `ArtifactExpired` (a retention policy
//! decided) **or** an [`ArtifactDeleted`](crate::events::ArtifactDeleted)
//! (a caller deleted the artifact through the registry API). Both retire
//! an artifact from service and both must release its
//! `content_references` source edges so refcount-gated GC can reach the
//! bytes; `ArtifactPurged` terminates either one.
//!
//! The delete path needs no separate collector and no synthetic
//! retention vocabulary. `ArtifactDeleted` already commits in the same
//! transaction as `artifacts.deleted_at` (`PgArtifactRepository::delete`),
//! so the work item is durable exactly when the retirement is — the
//! property the terminal-transition atomicity depends on — and reusing
//! this one destructive path is what keeps the crash-safety invariants
//! (durable worklist, per-hash checkpoint, atomic terminal batch) stated
//! once rather than re-earned by a second sweep.
//!
//! # Why a separate port (not methods on
//! [`ContentReferenceIndex`](super::content_reference_index::ContentReferenceIndex))
//!
//! Identical reasoning to the
//! [`RefcountReconcilePort`](super::refcount_reconcile::RefcountReconcilePort)
//! split. `ContentReferenceIndex` owns ordinary reference CRUD; the
//! purge worklist and atomic terminal transition are a different
//! transactional responsibility. Keeping them on this dedicated port
//! prevents purge-specific state from leaking into general reference
//! operations.
//!
//! # Why the port returns refcount *decisions* (data), not a "purge" verb
//!
//! Keeping the transactional decrement, storage delete, and terminal
//! transition as separate concerns that exchange typed decision data
//! lets the `hort-app` `PurgeUseCase` stay pure
//! orchestration (100% mock-testable — the release-gate re-assertion, the
//! two-stage idempotency split, the `info!`/`warn!`/`error!` policy, the
//! summary) while the SQL (row lock, set-based `DELETE … RETURNING`,
//! cross-`kind` count) stays in the Postgres adapter (≥85%
//! integration-tested). The use case never embeds SQL; the adapter never
//! embeds the tracing/summary/idempotency-orchestration policy.

use uuid::Uuid;

use chrono::{DateTime, Utc};

use crate::entities::artifact::QuarantineStatus;
use crate::error::DomainResult;
use crate::ports::event_store::AppendEvents;
use crate::types::ContentHash;

use super::BoxFuture;

/// One artifact with a pending byte-release work item — an
/// `ArtifactExpired` or an
/// [`ArtifactDeleted`](crate::events::ArtifactDeleted) with no following
/// `ArtifactPurged` — that the GC walk must process. Carries the
/// quarantine status so the use case can re-assert the release-gate
/// invariant (defence-in-depth) before any destructive step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPurge {
    /// The artifact whose work item is pending purge. Also the
    /// `entity_id` of its artifact stream.
    pub artifact_id: Uuid,
    /// Status as projected at scan time — used only to re-assert the
    /// release-gate invariant (the adapter already excludes the protected
    /// states; this is the conservative second check).
    pub quarantine_status: QuarantineStatus,
    /// `true` iff a mutable ref **in this artifact's own repository**
    /// currently resolves to this artifact (an OCI tag on its content
    /// hash, or a version pointer naming its `(name, version)` — the
    /// npm dist-tag shape). Read at sweep time, not at expiry time:
    /// that is the entire point of carrying it.
    ///
    /// ## Why the purge re-asks
    ///
    /// Evaluation and purge are separate sweeps, an hour apart by
    /// default. A tag added in between finds the artifact already
    /// carrying its `ArtifactExpired`, and nothing re-runs the
    /// predicate — so the steady state is correct and the interval is
    /// not. Re-reading the fact here closes that window: the last
    /// reader before the destructive step is the one that decides.
    pub tag_targeted: bool,
    /// `true` iff **every** pending `ArtifactExpired` on this
    /// artifact's stream carries a `KeepLastN` reason.
    ///
    /// The tag exemption belongs to `KeepLastN` alone: an age- or
    /// security-driven policy is the operator's explicit instruction
    /// to remove old or vulnerable content, and a tag does not
    /// countermand it. So an artifact that some *other* policy also
    /// expired is purged even while tagged — the `KeepLastN` decision
    /// is simply not the one keeping it in the work set.
    ///
    /// Vacuously `true` for an artifact whose only work item is a
    /// delete: there is no expiry decision to disqualify it. Read
    /// [`Self::user_deleted`] alongside it — the fields state two
    /// separate facts and the exemption decision composes them in the
    /// use case, which is where the skip stays observable.
    pub expired_only_by_keep_last_n: bool,
    /// `true` iff an [`ArtifactDeleted`](crate::events::ArtifactDeleted)
    /// is on this artifact's stream — a caller deleted it through the
    /// registry API, which is itself a byte-release work item.
    ///
    /// Reported because a deletion is not an expiry and must not
    /// inherit the `KeepLastN` tag exemption: a delete is the caller's
    /// explicit instruction to remove the artifact, exactly like an
    /// age- or security-driven policy, and a mutable ref left pointing
    /// at a row no read path can resolve does not countermand it.
    pub user_deleted: bool,
}

/// One refcount decision the adapter's transactional decrement step
/// produced for a single CAS hash referenced by the purged artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgedRef {
    /// The CAS content hash whose `content_references` row(s) for this
    /// artifact were removed. The purge worklist preserves it after
    /// those source edges are gone.
    pub content_hash: ContentHash,
    /// Cross-`kind` `content_references` count for `content_hash`
    /// **after** this artifact's references were removed.
    /// `0` ⇒ the blob is GC-eligible and must be deleted; `> 0` ⇒ a
    /// live reference keeps the blob and only this ref is gone.
    pub refs_remaining: u32,
    /// Whether the corresponding storage decision has completed. A
    /// retry skips completed hashes but retains them so the final
    /// transaction can append one terminal event per hash.
    pub completed: bool,
}

/// A **held** hash-scoped blob-reclamation lock.
///
/// Handed back by [`PurgeGcPort::begin_blob_reclaim`] when the lock was
/// taken *and* the cross-`kind` reference count for the hash was still
/// `0` under it. While it is alive no other session can record a
/// `content_references` row for that hash, so the storage delete the
/// caller performs next cannot race a re-reference.
///
/// # The contract the guard carries
///
/// The lock has to span a commit boundary: the reference bookkeeping
/// commits in one transaction and [`StoragePort`](super::storage::StoragePort)`::delete`
/// runs afterwards, in the application layer. A transaction-scoped lock
/// released at that commit would not cover the delete — so the guard
/// *is* the open transaction, and the delete happens underneath it.
///
/// **Release it after the storage call, on every path** (success and
/// failure alike). Dropping the guard without calling
/// [`release`](Self::release) must also release the lock — an
/// implementation may not leave a lock standing behind a lost
/// guard — but `release` is the path that reports a failure to do so.
pub trait BlobReclaimGuard: Send {
    /// Release the lock. Consumes the guard; the caller must have
    /// finished its storage call first.
    fn release(self: Box<Self>) -> BoxFuture<'static, DomainResult<()>>;
}

/// Outcome of [`PurgeGcPort::begin_blob_reclaim`] — the three answers a
/// destructive sweep is allowed to get, and only one of them authorises
/// a delete.
///
/// The posture is **skip when in doubt**: two of the three outcomes
/// leave the bytes standing. They are not the same skip.
/// [`Contended`](Self::Contended) is a *deferral* — nothing was read,
/// nothing was changed, the worklist row stands and the next sweep asks
/// again. [`Referenced`](Self::Referenced) is a *keep* — the answer is
/// in, the blob is alive, and the purge finishes without it.
pub enum BlobReclaim {
    /// The lock is held and the hash had **zero** references under it.
    /// The caller may delete the bytes, and must
    /// [`release`](BlobReclaimGuard::release) the guard afterwards.
    Granted(Box<dyn BlobReclaimGuard>),
    /// The lock was taken, and under it the hash turned out to have
    /// `refs_now > 0` live references — the worklist's `0` was a stale
    /// snapshot and something re-referenced these bytes since. The blob
    /// is alive: do not delete it. The lock is already released.
    ///
    /// This is a *terminal* answer, not a deferral: a reference that
    /// exists now keeps the blob, and re-asking forever would leave the
    /// artifact's purge permanently unfinishable. The worklist row is
    /// refreshed to `refs_now` so the `ArtifactPurged` the caller
    /// emits states the count that actually held.
    Referenced {
        /// The cross-`kind` `content_references` count observed under
        /// the lock.
        refs_now: u32,
    },
    /// Another session holds the hash lock — a concurrent ingest is
    /// recording a reference to exactly these bytes, or a second sweep
    /// is already reclaiming them. Nothing was read and nothing was
    /// changed. Leave the bytes and the worklist row; the next sweep
    /// retries.
    Contended,
}

impl std::fmt::Debug for BlobReclaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Granted(_) => f.write_str("Granted(..)"),
            Self::Referenced { refs_now } => f
                .debug_struct("Referenced")
                .field("refs_now", refs_now)
                .finish(),
            Self::Contended => f.write_str("Contended"),
        }
    }
}

/// Read + transactional-transition outbound port for the storage-GC
/// walk. The Postgres adapter owns the worklist, reference deletion,
/// completion checkpoints, and atomic event/projection transition;
/// unit tests use an in-memory mock.
pub trait PurgeGcPort: Send + Sync {
    /// Every artifact carrying a byte-release work item — an
    /// `ArtifactExpired` **or** an
    /// [`ArtifactDeleted`](crate::events::ArtifactDeleted) — with **no**
    /// following `ArtifactPurged`: the pending-purge work set.
    /// MUST exclude `quarantine_status ∈ {quarantined, rejected,
    /// scan_indeterminate}`; the use case re-asserts this regardless
    /// (defence-in-depth).
    ///
    /// Tag-targeted artifacts are **not** excluded here — the
    /// adapter reports the facts ([`PendingPurge::tag_targeted`],
    /// [`PendingPurge::expired_only_by_keep_last_n`] and
    /// [`PendingPurge::user_deleted`]) and the use case owns the
    /// decision, so the skip is observable in the sweep summary instead
    /// of vanishing into a `WHERE` clause.
    ///
    /// **Paged, and the caller owns the page cap.** The pending set is
    /// only known once it is fully loaded, and on the first sweep after
    /// a deployment it is the whole backlog — so the port never hands
    /// back an unbounded result. `limit` bounds one page;
    /// `after_artifact_id` is the exclusive keyset position (`None`
    /// starts at the beginning). Rows come back ordered by
    /// `artifact_id` so the caller can pass the last one back as the
    /// next page's `after_artifact_id`.
    fn list_pending_purge(
        &self,
        limit: u32,
        after_artifact_id: Option<Uuid>,
    ) -> BoxFuture<'_, DomainResult<Vec<PendingPurge>>>;

    /// Prepare the durable worklist in **one committed, idempotent
    /// transaction**: lock the artifact row, delete every source edge,
    /// compute each distinct target's cross-kind remaining count, and
    /// persist those decisions before returning them.
    ///
    /// **Idempotent**: once present, the worklist is authoritative and
    /// returned unchanged on retry. This preserves OCI membership
    /// targets that no artifact column can reconstruct after deletion.
    fn purge_artifact_refs(&self, artifact_id: Uuid)
        -> BoxFuture<'_, DomainResult<Vec<PurgedRef>>>;

    /// Take the hash-scoped blob-reclamation lock and re-verify, under
    /// it, that the hash still has **zero** `content_references`.
    ///
    /// This is the authorisation for the destructive step, and it
    /// exists because the worklist's `refs_remaining` is a snapshot:
    /// it was computed in the preparation transaction, which has long
    /// since committed, and a retry can run the delete sweeps later.
    /// A count that was `0` then says nothing about now.
    ///
    /// The lock is the same one every `content_references` write takes,
    /// so a re-reference of these bytes is either already committed
    /// (and counted here) or blocked behind this lock until the guard
    /// is released.
    ///
    /// Returns [`BlobReclaim::Granted`] with a live guard the caller
    /// holds across
    /// [`StoragePort::delete`](super::storage::StoragePort::delete),
    /// [`BlobReclaim::Referenced`] when the hash is alive after all
    /// (and the worklist row is refreshed to the observed count so the
    /// terminal `ArtifactPurged` states it), or
    /// [`BlobReclaim::Contended`] when the lock is held elsewhere.
    ///
    /// **Never blocks.** A destructive sweep that waits on a lock held
    /// by a live ingest is a sweep that has decided its housekeeping
    /// outranks a request; it does not. Contention is an answer, and
    /// the answer is "not this run".
    fn begin_blob_reclaim(
        &self,
        artifact_id: Uuid,
        content_hash: &ContentHash,
    ) -> BoxFuture<'_, DomainResult<BlobReclaim>>;

    /// Checkpoint one hash after its storage decision succeeds. The
    /// operation is idempotent so a delete-success/checkpoint-failure
    /// crash safely retries a success-on-missing delete.
    fn mark_purge_ref_complete(
        &self,
        artifact_id: Uuid,
        content_hash: &ContentHash,
        completed_at: DateTime<Utc>,
    ) -> BoxFuture<'_, DomainResult<()>>;

    /// Append every per-hash `ArtifactPurged` event and set
    /// `artifacts.deleted_at` in one transaction. The adapter refuses
    /// the transition while any worklist row is incomplete. `events`
    /// is assembled by the application layer so attribution and event
    /// vocabulary remain orchestration policy, not adapter policy.
    ///
    /// The retirement is idempotent in the *state*: the transition
    /// succeeds whenever the row ends up retired — including when the
    /// user-facing delete path retired it first, which keeps its
    /// earlier timestamp — and reports `NotFound` only when the row is
    /// genuinely absent.
    fn complete_artifact_purge(
        &self,
        artifact_id: Uuid,
        retired_at: DateTime<Utc>,
        events: AppendEvents,
    ) -> BoxFuture<'_, DomainResult<()>>;
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
        fn list_pending_purge(
            &self,
            _limit: u32,
            _after_artifact_id: Option<Uuid>,
        ) -> BoxFuture<'_, DomainResult<Vec<PendingPurge>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn begin_blob_reclaim(
            &self,
            _artifact_id: Uuid,
            _content_hash: &ContentHash,
        ) -> BoxFuture<'_, DomainResult<BlobReclaim>> {
            Box::pin(async { Ok(BlobReclaim::Contended) })
        }
        fn purge_artifact_refs(
            &self,
            _artifact_id: Uuid,
        ) -> BoxFuture<'_, DomainResult<Vec<PurgedRef>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn mark_purge_ref_complete(
            &self,
            _artifact_id: Uuid,
            _content_hash: &ContentHash,
            _completed_at: DateTime<Utc>,
        ) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
        fn complete_artifact_purge(
            &self,
            _artifact_id: Uuid,
            _retired_at: DateTime<Utc>,
            _events: AppendEvents,
        ) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn empty_port_returns_no_pending_and_no_refs() {
        let p = EmptyPort;
        assert!(p.list_pending_purge(10, None).await.unwrap().is_empty());
        assert!(p.purge_artifact_refs(Uuid::nil()).await.unwrap().is_empty());
        assert!(matches!(
            p.begin_blob_reclaim(Uuid::nil(), &hash(HASH_A))
                .await
                .unwrap(),
            BlobReclaim::Contended
        ));
        p.mark_purge_ref_complete(Uuid::nil(), &hash(HASH_A), Utc::now())
            .await
            .unwrap();
        p.complete_artifact_purge(
            Uuid::nil(),
            Utc::now(),
            AppendEvents {
                stream_id: crate::events::StreamId::artifact(Uuid::nil()),
                expected_version: crate::ports::event_store::ExpectedVersion::Any,
                events: Vec::new(),
                correlation_id: Uuid::nil(),
                causation_id: None,
                actor: crate::events::system_actor(),
            },
        )
        .await
        .unwrap();
    }

    /// `DomainError` round-trips through every return signature — the
    /// adapter surfaces SQL failures this way and the use case maps
    /// them to `AppError::Domain`.
    #[tokio::test]
    async fn errors_round_trip_through_port_signatures() {
        use crate::error::DomainError;
        struct ErrPort;
        impl PurgeGcPort for ErrPort {
            fn list_pending_purge(
                &self,
                _limit: u32,
                _after_artifact_id: Option<Uuid>,
            ) -> BoxFuture<'_, DomainResult<Vec<PendingPurge>>> {
                Box::pin(async { Err(DomainError::Invariant("pending list failed".into())) })
            }
            fn begin_blob_reclaim(
                &self,
                _artifact_id: Uuid,
                _content_hash: &ContentHash,
            ) -> BoxFuture<'_, DomainResult<BlobReclaim>> {
                Box::pin(async { Err(DomainError::Invariant("reclaim lease failed".into())) })
            }
            fn purge_artifact_refs(
                &self,
                _artifact_id: Uuid,
            ) -> BoxFuture<'_, DomainResult<Vec<PurgedRef>>> {
                Box::pin(async { Err(DomainError::Invariant("purge tx failed".into())) })
            }
            fn mark_purge_ref_complete(
                &self,
                _artifact_id: Uuid,
                _content_hash: &ContentHash,
                _completed_at: DateTime<Utc>,
            ) -> BoxFuture<'_, DomainResult<()>> {
                Box::pin(async { Err(DomainError::Invariant("checkpoint failed".into())) })
            }
            fn complete_artifact_purge(
                &self,
                _artifact_id: Uuid,
                _retired_at: DateTime<Utc>,
                _events: AppendEvents,
            ) -> BoxFuture<'_, DomainResult<()>> {
                Box::pin(async { Err(DomainError::Invariant("completion failed".into())) })
            }
        }
        let p = ErrPort;
        assert!(matches!(
            p.list_pending_purge(10, None).await.unwrap_err(),
            DomainError::Invariant(_)
        ));
        assert!(matches!(
            p.begin_blob_reclaim(Uuid::nil(), &hash(HASH_A))
                .await
                .unwrap_err(),
            DomainError::Invariant(_)
        ));
        assert!(matches!(
            p.purge_artifact_refs(Uuid::nil()).await.unwrap_err(),
            DomainError::Invariant(_)
        ));
        assert!(matches!(
            p.mark_purge_ref_complete(Uuid::nil(), &hash(HASH_A), Utc::now())
                .await
                .unwrap_err(),
            DomainError::Invariant(_)
        ));
        assert!(matches!(
            p.complete_artifact_purge(
                Uuid::nil(),
                Utc::now(),
                AppendEvents {
                    stream_id: crate::events::StreamId::artifact(Uuid::nil()),
                    expected_version: crate::ports::event_store::ExpectedVersion::Any,
                    events: Vec::new(),
                    correlation_id: Uuid::nil(),
                    causation_id: None,
                    actor: crate::events::system_actor(),
                },
            )
            .await
            .unwrap_err(),
            DomainError::Invariant(_)
        ));
    }

    /// The three reclamation outcomes are distinguishable and the
    /// granted one hands back a guard that releases. `Debug` is
    /// exercised on every arm: it is what a sweep's `tracing` field
    /// renders, and a guard arm that printed its transaction would put
    /// connection state in a log line.
    #[tokio::test]
    async fn blob_reclaim_outcomes_round_trip_and_the_guard_releases() {
        struct Guard;
        impl BlobReclaimGuard for Guard {
            fn release(self: Box<Self>) -> BoxFuture<'static, DomainResult<()>> {
                Box::pin(async { Ok(()) })
            }
        }

        let granted = BlobReclaim::Granted(Box::new(Guard));
        assert_eq!(format!("{granted:?}"), "Granted(..)");
        let BlobReclaim::Granted(guard) = granted else {
            panic!("constructed Granted");
        };
        guard.release().await.expect("release");

        let referenced = BlobReclaim::Referenced { refs_now: 3 };
        assert_eq!(format!("{referenced:?}"), "Referenced { refs_now: 3 }");
        assert!(matches!(
            referenced,
            BlobReclaim::Referenced { refs_now: 3 }
        ));

        assert_eq!(format!("{:?}", BlobReclaim::Contended), "Contended");
    }

    /// The data types are plain value structs — round-trip equality +
    /// the `quarantine_status` field carries through (used by the
    /// use-case release-gate re-assertion).
    #[test]
    fn data_types_round_trip() {
        let a = Uuid::new_v4();
        let pp = PendingPurge {
            artifact_id: a,
            quarantine_status: QuarantineStatus::Released,
            tag_targeted: true,
            expired_only_by_keep_last_n: true,
            user_deleted: true,
        };
        assert_eq!(pp.clone(), pp);
        assert_eq!(pp.artifact_id, a);
        assert_eq!(pp.quarantine_status, QuarantineStatus::Released);
        assert!(pp.tag_targeted);
        assert!(pp.expired_only_by_keep_last_n);
        assert!(pp.user_deleted);

        let pr = PurgedRef {
            content_hash: hash(HASH_A),
            refs_remaining: 0,
            completed: false,
        };
        assert_eq!(pr.clone(), pr);
        assert_eq!(pr.content_hash.as_ref(), HASH_A);
        assert_eq!(pr.refs_remaining, 0);
        assert!(!pr.completed);
    }
}
