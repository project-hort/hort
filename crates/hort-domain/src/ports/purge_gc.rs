//! Outbound port the **storage-GC walk**
//! (`PurgeUseCase::process_expired`) uses: read
//! the pending-purge work set and, in one committed idempotent
//! transaction, retire the artifact projection, decrement the
//! `content_references` projection and
//! persist and report the post-delete cross-`kind` remaining count per
//! CAS hash. Storage completion is checkpointed per hash; only after
//! every checkpoint exists may the adapter atomically append all
//! terminal events.
//!
//! **The retirement is first, not last.** `artifacts.deleted_at` is
//! written by [`PurgeGcPort::purge_artifact_refs`], in the same commit
//! as the edge deletion and therefore before any byte is destroyed,
//! rather than by the terminal transition at the end of the sweep —
//! see that method's docs for the window this closes.
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
//! CAS blob iff nothing claims it any more — neither a cross-`kind`
//! `content_references` row nor a GC-protected artifact holding the hash
//! without one, see [`BlobReclaim::ProtectedClaim`] — and append every
//! `ArtifactPurged`).
//! The `hort-app` `PurgeUseCase` is pure orchestration over this port plus
//! the existing [`StoragePort`](super::storage::StoragePort) and the event
//! store; the SQL (lock + `DELETE … RETURNING` + cross-`kind` count +
//! protected-claim count) lives in the Postgres adapter.
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
//! # The page is a snapshot; the lock is where the decision belongs
//!
//! Two rules keep content out of the destructive path: retained scan
//! evidence is never collected ([`PendingPurge::is_gc_protected`]) and
//! a `KeepLastN` tag target is exempt
//! ([`PendingPurge::is_tag_exempt`]). Both are computed from facts that
//! change while the sweep runs — a scan verdict lands, a tag is set.
//!
//! [`PurgeGcPort::list_pending_purge`] reports those facts for a whole
//! page, and the sweep's own evaluation of them is a **pre-exit**: it
//! saves taking a lock, and nothing more. The authority sits in
//! [`PurgeGcPort::purge_artifact_refs`], which re-reads the same four
//! facts under the artifact lock in the transaction that deletes the
//! edges, and refuses there. Same shape as `mutable_refs`'s `set`: the
//! adapter's in-transaction `FOR UPDATE` re-read is the race defence
//! and the use case's earlier read is the optimisation.
//!
//! Two things make that re-read load-bearing rather than merely
//! fresher, and an implementation owes both:
//!
//! - **The lock has to reach every writer of the facts.** Three of the
//!   four live outside the artifact row — the tag in the ref
//!   projection, the two expiry facts on the artifact's stream — so a
//!   lock the ref-write path does not take leaves the tag fact
//!   unguarded (see [`RefLifecyclePort`](super::ref_lifecycle::RefLifecyclePort)).
//! - **The facts have to be read after the lock is held, not while
//!   taking it.** Under read-committed isolation a statement answers
//!   subqueries from the snapshot it opened with, so a statement that
//!   both acquires the lock and reads the facts reports the state at
//!   the moment its *wait began* — a write that committed during the
//!   wait stays invisible to the transaction that waited for it. The
//!   lock and the read are therefore two statements.
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
/// `ArtifactPurged` — that the GC walk must process. Carries the six
/// facts the two protection rules
/// ([`Self::is_gc_protected`], [`Self::is_tag_exempt`]) are computed
/// from.
///
/// # Two readers, one set of facts
///
/// The same struct is produced twice per artifact, by two readers with
/// different authority:
///
/// 1. [`PurgeGcPort::list_pending_purge`] fills a whole **page** of
///    them. The sweep evaluates both rules on that page row as a cheap
///    pre-exit — it saves taking the artifact lock for an artifact that
///    is visibly protected — and that is *all* it is. A page row is a
///    snapshot taken before the sweep processed any item of the page.
/// 2. [`PurgeGcPort::purge_artifact_refs`] fills one, freshly, under
///    the artifact lock it takes in the transaction that does the
///    deleting, and refuses the destructive step itself
///    ([`PurgePreparation::Protected`] /
///    [`PurgePreparation::TagExempt`]). That reader is the one whose
///    answer is load-bearing.
///
/// The split matters because the gap between reader 1 and the
/// destructive step of a given item contains the complete processing of
/// every preceding item of its page, storage deletes included — the
/// longest interval in the sweep, not the shortest. A scan moving an
/// artifact to `rejected` inside it, or a tag landing on a `KeepLastN`
/// target, is invisible to the page row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPurge {
    /// The artifact whose work item is pending purge. Also the
    /// `entity_id` of its artifact stream.
    pub artifact_id: Uuid,
    /// The artifact's quarantine status, as observed by whichever
    /// reader produced this value (see the type docs) — the input to
    /// [`Self::is_gc_protected`].
    pub quarantine_status: QuarantineStatus,
    /// `true` iff a mutable ref **in this artifact's own repository**
    /// currently resolves to this artifact (an OCI tag on its content
    /// hash, or a version pointer naming its `(name, version)` — the
    /// npm dist-tag shape).
    ///
    /// ## Why the purge asks at all
    ///
    /// Evaluation and purge are separate sweeps, an hour apart by
    /// default. A tag added in between finds the artifact already
    /// carrying its `ArtifactExpired`, and nothing re-runs the
    /// predicate — so the steady state is correct and the interval is
    /// not. Which reader's value this is decides how much of that
    /// interval is actually covered: see the type docs.
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
    /// separate facts and [`Self::is_tag_exempt`] is the one place that
    /// composes them.
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
    /// `true` iff a pending
    /// [`ArtifactExpired`](crate::events::ArtifactExpired) on this
    /// artifact's stream carries a `held_state_authority` that matches
    /// **this occupancy** of the artifact's **current** held state:
    /// same state, and an `entry_stream_position` equal to the stream
    /// position of the latest entry event for that state.
    ///
    /// Only [`Self::is_gc_protected`] reads it, and only when the
    /// status is held — for a `none` / `released` artifact the value
    /// decides nothing, because there is no protection for it to lift.
    ///
    /// ## Why the authority and not the status
    ///
    /// A held status says what the artifact *is*. It never says that
    /// anything authorised disposing of it, which is why the bare
    /// status could only ever be a refusal. The authority is the
    /// opposite kind of fact: a retention policy named this held state,
    /// evaluated this artifact, found its age bound elapsed **in that
    /// state**, and recorded the decision immutably on the stream. So
    /// this is the one thing that may lift the refusal, and an artifact
    /// that reached the pending set without it is still refused —
    /// which is the defence against the accidental case that the status
    /// filter used to be.
    ///
    /// ## Why "this occupancy" and not "this state"
    ///
    /// All three held states are re-enterable. An artifact rejected in
    /// March, expired by a policy whose span had run, released by a
    /// curator and rejected again in September is `rejected` both
    /// times, and the March decision says nothing about the September
    /// occupancy — whose own span has not elapsed. Matching on the
    /// state name alone would purge it. The position is per-stream,
    /// monotonic and append-only, so a match on it cannot be satisfied
    /// by a later entry.
    ///
    /// A legacy `ArtifactExpired` — one written before the authority
    /// field existed — carries none, so it reads `false`: it
    /// authorises nothing on the held-state axis.
    pub held_state_authorised: bool,
    /// `true` iff the **only** thing on this artifact's stream that
    /// authorises collecting it is a held-state expiry: some pending
    /// `ArtifactExpired` carries a `held_state_authority`, and no work
    /// item authorises collection unconditionally — no
    /// [`ArtifactDeleted`](crate::events::ArtifactDeleted) and no
    /// `ArtifactExpired` without an authority.
    ///
    /// `false` for every artifact that reached the pending set before
    /// the held-state exception existed, and `false` for an artifact
    /// with no work item at all, so the arm that reads it
    /// ([`Self::is_gc_protected`]'s serving-status arm) decides exactly
    /// as it always did for them.
    ///
    /// ## What it is for
    ///
    /// A held-state expiry is a **conditional** work item: it
    /// authorises collection only while the occupancy it names holds.
    /// An artifact whose only work item is one, and which is no longer
    /// in that state, therefore has nothing authorising its
    /// collection — and the commonest way for an occupancy to end is a
    /// curator *releasing* the artifact, which is a human saying "serve
    /// this". Reading the serving status alone would collect it,
    /// because a `released` artifact is collectable and a pending
    /// `ArtifactExpired` is a work item; this fact is what
    /// distinguishes "something decided to collect these bytes" from
    /// "something decided to collect these bytes **while they were
    /// evidence**".
    ///
    /// Stated as "only a held-state expiry authorises this" rather than
    /// as "nothing unconditional authorises this" so that an artifact
    /// with **no** work item reads `false`. Such an artifact is never
    /// offered by [`PurgeGcPort::list_pending_purge`], so the value
    /// decides nothing in the sweep — but
    /// [`PurgeGcPort::purge_artifact_refs`] is also reachable directly,
    /// and answering `Protected` there would report an absent work item
    /// as retained evidence, which is a different fact.
    ///
    /// Fail-safe in the direction that keeps bytes: an `ArtifactExpired`
    /// whose `held_state_authority` is present but unreadable counts as
    /// conditional, so it authorises nothing by itself.
    pub collection_needs_held_state_authority: bool,
}

impl PendingPurge {
    /// `true` iff this artifact is **retained scan evidence** that
    /// nothing authorised disposing of, and must therefore never be
    /// purged: a held status (`quarantined`, `rejected` or
    /// `scan_indeterminate`) with no matching
    /// [`Self::held_state_authorised`].
    ///
    /// The status is what makes an artifact evidence; the authority is
    /// what makes disposing of it a decision somebody recorded. Neither
    /// alone is the rule, and the composition is deliberately
    /// asymmetric: a `none` / `released` artifact is collectable
    /// whatever the authority says (there was nothing to authorise),
    /// and a held artifact is refused unless the authority names its
    /// current occupancy.
    ///
    /// Stage one already refuses a held artifact no policy opted in
    /// for, and [`PurgeGcPort::list_pending_purge`] excludes one from
    /// the work set as well — so a `true` here means one of those
    /// filters was bypassed, or the status changed after they ran, or
    /// the artifact re-entered its held state after the expiry was
    /// recorded. Every one of those is a reason to stop rather than to
    /// investigate first: the next step is destructive.
    ///
    /// Exhaustive by construction — no wildcard arm — so a new
    /// [`QuarantineStatus`] variant is a compile error here rather than
    /// a state that silently defaults to collectable.
    pub fn is_gc_protected(&self) -> bool {
        match self.quarantine_status {
            // Held: evidence, unless a policy named this very
            // occupancy and its span has run.
            QuarantineStatus::Quarantined
            | QuarantineStatus::Rejected
            | QuarantineStatus::ScanIndeterminate => !self.held_state_authorised,
            // Serving: collectable, unless the only thing authorising
            // collection is a held-state expiry — whose occupancy, for
            // an artifact in a serving status, has by definition ended.
            // A curator releasing a rejected artifact is the commonest
            // way for that to happen, and it is the one case where a
            // serving status must still refuse.
            QuarantineStatus::None | QuarantineStatus::Released => {
                self.collection_needs_held_state_authority
            }
        }
    }

    /// `true` iff the `KeepLastN` tag exemption applies: a mutable ref
    /// in the artifact's own repository resolves to it, **every**
    /// pending expiry decision on its stream is `KeepLastN`, and no
    /// caller-facing delete was requested.
    ///
    /// The rule is a conjunction of three facts and each conjunct earns
    /// its place:
    ///
    /// - [`Self::tag_targeted`] — the exemption exists so a live tag
    ///   never resolves to bytes the sweep removed.
    /// - [`Self::expired_only_by_keep_last_n`] — the exemption belongs
    ///   to `KeepLastN` alone. An age- or security-driven policy is the
    ///   operator's explicit instruction to remove the content, and a
    ///   tag does not countermand it; an artifact some *other* policy
    ///   also expired is purged even while tagged.
    /// - `!`[`Self::user_deleted`] — a caller-facing delete is that
    ///   same class of explicit instruction, and
    ///   `expired_only_by_keep_last_n` is vacuously true for an
    ///   artifact carrying no expiry decision at all. Without this
    ///   conjunct a tagged artifact's delete would be exempted by the
    ///   rule for a policy that never ran, and its bytes would be held
    ///   by a mutable ref pointing at a row no read path resolves.
    ///
    /// One function because the rule has two readers (see the type
    /// docs) and a rule with two authors is a rule that will differ
    /// from itself.
    pub fn is_tag_exempt(&self) -> bool {
        self.tag_targeted && self.expired_only_by_keep_last_n && !self.user_deleted
    }
}

/// One refcount decision the adapter's transactional decrement step
/// produced for a single CAS hash referenced by the purged artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurgedRef {
    /// The CAS content hash whose `content_references` row(s) for this
    /// artifact were removed. The purge worklist preserves it after
    /// those source edges are gone.
    pub content_hash: ContentHash,
    /// Claims on `content_hash` **after** this artifact's references
    /// were removed. `0` ⇒ nothing seen so far holds the blob; `> 0` ⇒
    /// something does, and only this ref is gone.
    ///
    /// As produced by [`PurgeGcPort::purge_artifact_refs`] this is the
    /// cross-`kind` `content_references` count, and a `0` means
    /// "GC-eligible **so far**" rather than "delete it": the count is a
    /// snapshot from a transaction that has already committed, and
    /// `content_references` is not the only kind of claim. The
    /// authoritative answer comes from
    /// [`PurgeGcPort::begin_blob_reclaim`] under the blob lock, which
    /// also counts GC-protected artifacts that hold the hash without an
    /// edge ([`BlobReclaim::ProtectedClaim`]) and refreshes this field
    /// to whatever it observed — so the value that reaches
    /// `ArtifactPurged` is a claim count, not a row count.
    pub refs_remaining: u32,
    /// Whether the corresponding storage decision has completed. A
    /// retry skips completed hashes but retains them so the final
    /// transaction can append one terminal event per hash.
    pub completed: bool,
}

/// Outcome of [`PurgeGcPort::purge_artifact_refs`] — the durable
/// worklist, or one of the three reasons there is none.
///
/// The three non-`Prepared` answers are deliberately distinct values
/// rather than an empty worklist. They mean different things, the
/// caller counts and logs them differently, and an empty `Vec` saying
/// all three at once is how a protection refusal would come to be
/// reported as "nothing to do".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PurgePreparation {
    /// The worklist for this artifact: every hash whose source edges
    /// were released, with the post-delete claim count and the
    /// completion checkpoint per hash. Authoritative and idempotent —
    /// a retry gets the same rows back.
    ///
    /// The artifact is **retired** (`artifacts.deleted_at` set) in the
    /// same commit — see
    /// [`PurgeGcPort::purge_artifact_refs`]. This is the only outcome
    /// that writes it.
    Prepared(Vec<PurgedRef>),
    /// There is no `artifacts` row with this id. Nothing was locked,
    /// read, deleted or retired. Not an error and not a protection
    /// refusal: the row the page offered is gone, so there is no
    /// artifact left to release bytes for, and it will not be offered
    /// again. The worklist is `ON DELETE CASCADE`-tied to the row, so a
    /// vanished artifact takes its work with it.
    NoArtifact,
    /// The artifact is **GC-protected evidence** as of the read taken
    /// under the artifact lock, in the transaction that would have done
    /// the deleting ([`PendingPurge::is_gc_protected`]). Nothing was
    /// deleted: no `content_references` edge, no worklist row, no
    /// event, and no retirement — `deleted_at` is left exactly as it
    /// was found, so a protection that declines to delete does not
    /// take the artifact out of service. The work item stays pending
    /// and the next sweep asks again.
    ///
    /// Reaching this is not routine. The page row the caller already
    /// checked said the artifact was collectable, so this is the
    /// interval closing on a status that changed *inside* the sweep —
    /// a scan verdict landing while the sweep worked through the
    /// preceding items of the page.
    Protected {
        /// The status observed under the lock, for the caller's log —
        /// which of the protected states it turned into is the whole
        /// content of the warning.
        status: QuarantineStatus,
    },
    /// The `KeepLastN` tag exemption applies as of the read taken under
    /// the artifact lock ([`PendingPurge::is_tag_exempt`]). Nothing was
    /// deleted and nothing was retired, exactly as for
    /// [`Self::Protected`], and the artifact is purged on a later sweep
    /// once the tag moves.
    ///
    /// Same note as above: the caller's page row said otherwise, so
    /// this is a tag that landed on a `KeepLastN` target inside the
    /// sweep's own window.
    TagExempt,
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

/// Outcome of [`PurgeGcPort::begin_blob_reclaim`] — the four answers a
/// destructive sweep is allowed to get, and only one of them authorises
/// a delete.
///
/// The posture is **skip when in doubt**: three of the four outcomes
/// leave the bytes standing. They are not the same skip.
/// [`Contended`](Self::Contended) is a *deferral* — nothing was read,
/// nothing was changed, the worklist row stands and the next sweep asks
/// again. [`Referenced`](Self::Referenced) and
/// [`ProtectedClaim`](Self::ProtectedClaim) are *keeps* — the answer is
/// in, the blob is alive, and the purge finishes without it. The two
/// keeps differ in what holds the bytes: a `content_references` row, or
/// a GC-protected artifact that has no such row and never will.
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
    /// The lock was taken, the hash had **zero** `content_references`
    /// rows under it — and `claimants` artifacts still hold these
    /// bytes anyway. The blob is alive: do not delete it. The lock is
    /// already released.
    ///
    /// A claimant is a non-deleted artifact in a GC-protected
    /// quarantine state (`quarantined` / `rejected` /
    /// `scan_indeterminate`) whose primary content **or** metadata blob
    /// is this hash. Those states are the retained evidence of a scan
    /// verdict, and the two protections that keep such an artifact out
    /// of the destructive sweeps protect the *artifact*: it is never
    /// offered as a purge candidate and never acquires an
    /// `ArtifactExpired`. Reclamation, however, happens at the level of
    /// the *bytes*, and CAS deduplicates them across artifacts — so a
    /// released sibling sharing the hash can carry the bytes of
    /// protected evidence to the storage delete with the protected
    /// artifact never having been a candidate for anything.
    ///
    /// # Why this is not [`Referenced`](Self::Referenced)
    ///
    /// Protected evidence has **no** `content_references` edge, by
    /// design: the refcount repair deliberately mints none for it, so
    /// that a repaired refcount cannot make a quarantined blob look
    /// GC-protected for the wrong reason. The count is therefore
    /// structurally zero and stays zero, which is exactly why the
    /// refcount re-read under the lock cannot see this claim.
    /// `Referenced`'s `refs_now` is *defined* as a
    /// `content_references` count; reporting a claim through it would
    /// state a row count that is provably zero.
    ///
    /// # Terminal, not a deferral
    ///
    /// Same reason as `Referenced`, and more strongly: a `rejected`
    /// artifact is permanent, so re-asking would never get a different
    /// answer and the sibling's purge would never finish. The worklist
    /// row is refreshed to `claimants` so the `ArtifactPurged` the
    /// caller emits states the claim count that actually held.
    ProtectedClaim {
        /// Distinct non-deleted GC-protected artifacts claiming this
        /// hash, counted under the lock. An artifact whose primary
        /// content and metadata blob are the same hash is one
        /// claimant, not two.
        claimants: u32,
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
            Self::ProtectedClaim { claimants } => f
                .debug_struct("ProtectedClaim")
                .field("claimants", claimants)
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
    /// (defence-in-depth), and
    /// [`Self::purge_artifact_refs`] asks again under the artifact lock
    /// — the page row this returns is a snapshot, and the decision that
    /// matters is taken where the deleting happens.
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
    /// transaction**: lock the artifact row, re-read the protection
    /// facts under that lock, **retire the artifact
    /// (`artifacts.deleted_at = retired_at`)**, delete every source
    /// edge, compute each distinct target's cross-kind remaining count,
    /// and persist those decisions before returning them.
    ///
    /// **Idempotent**: once present, the worklist is authoritative and
    /// returned unchanged on retry. This preserves OCI membership
    /// targets that no artifact column can reconstruct after deletion.
    ///
    /// # The retirement is here, not at the terminal transition
    ///
    /// `artifacts.deleted_at` is the one fact that takes the artifact
    /// out of service: `Artifact::is_downloadable` is false once it is
    /// set, and a read path that filters `deleted_at IS NULL` stops
    /// resolving the row at all. It therefore MUST be durable **before
    /// the first destructive step**, which is this transaction's own
    /// edge deletion — and so, transitively, before any
    /// [`StoragePort::delete`](super::storage::StoragePort::delete) the
    /// caller goes on to issue.
    ///
    /// Writing it at the terminal transition instead leaves a window
    /// that lasts as long as the whole sweep (the terminal transition
    /// waits for *every* hash of the artifact, and the sweep walks many
    /// artifacts before it): bytes already deleted, row still live, so
    /// the artifact is downloadable to the domain and the CAS read
    /// behind it fails. The reader gets an opaque `500` on something
    /// the API still advertises, instead of the honest `404` the
    /// retirement produces.
    ///
    /// `retired_at` is the caller's injected sweep clock so a retry is
    /// coherent with the terminal `ArtifactPurged`'s `purged_at`.
    /// Implementations MUST keep an **earlier** existing timestamp
    /// (`COALESCE(deleted_at, retired_at)`): a caller-facing delete
    /// already recorded the moment the artifact left service, and the
    /// purge time must not overwrite that audit fact.
    ///
    /// **Every `Prepared` outcome carries the retirement; no refusal
    /// does.** The two are one commit, so a reader never sees the edge
    /// deletion without the retirement, and
    /// [`PurgePreparation::Protected`] / [`PurgePreparation::TagExempt`]
    /// / [`PurgePreparation::NoArtifact`] leave `deleted_at` exactly as
    /// they found it — a protection that declines to delete must not
    /// take the artifact out of service.
    ///
    /// An aborted run therefore leaves a retired artifact with intact
    /// bytes, and that is the safe direction: the work item is
    /// untouched (membership is the event rule — see
    /// [`Self::list_pending_purge`] — not `deleted_at`), so the next
    /// sweep resumes and finishes it. The reverse — live row, deleted
    /// bytes — is the one state no retry can make correct.
    ///
    /// # The protection facts are re-read here, under the lock
    ///
    /// This is the last reader before the first destructive step, so it
    /// is the one that has to decide. Implementations MUST, after
    /// taking the artifact lock and before deleting any edge,
    /// re-read the four [`PendingPurge`] facts for this artifact and
    /// refuse the deletion when [`PendingPurge::is_gc_protected`] or
    /// [`PendingPurge::is_tag_exempt`] holds —
    /// [`PurgePreparation::Protected`] / [`PurgePreparation::TagExempt`],
    /// with the transaction ending without a `DELETE`. The caller's own
    /// evaluation of the same two rules on its page row is a cheap
    /// pre-exit that saves taking the lock; it is not this check, and
    /// it cannot be (see [`PendingPurge`]'s "two readers").
    ///
    /// The rules are [`PendingPurge`]'s methods rather than two
    /// re-derivations, because a protection rule with two authors is a
    /// rule that will eventually differ from itself.
    ///
    /// **Both refusals are re-askable.** Nothing is deleted and no
    /// event is appended, so the work item stays pending and the next
    /// sweep re-reads everything. That is the right posture for both:
    /// a quarantine status can be released and a tag can move.
    ///
    /// A refusal is **not** an empty worklist and not
    /// [`PurgePreparation::NoArtifact`] — the caller counts and logs
    /// the three apart.
    ///
    /// Once a worklist exists the edges are already gone, so a retry
    /// returns it ([`PurgePreparation::Prepared`]) and does not consult
    /// the facts: declining then would strand an artifact whose edges
    /// are deleted and whose terminal event can never be appended.
    /// What protects the *bytes* from that point on is
    /// [`Self::begin_blob_reclaim`]'s claim check, which asks about the
    /// hash rather than the artifact. The retry re-asserts the
    /// retirement rather than skipping it, so the invariant above holds
    /// branch-independently: a `Prepared` answer always comes from a
    /// transaction that also retired the row.
    fn purge_artifact_refs(
        &self,
        artifact_id: Uuid,
        retired_at: DateTime<Utc>,
    ) -> BoxFuture<'_, DomainResult<PurgePreparation>>;

    /// Take the hash-scoped blob-reclamation lock and re-verify, under
    /// it, that **nothing claims** the hash — neither a
    /// `content_references` row nor a GC-protected artifact.
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
    /// **Two kinds of claim, because the refcount only knows one.**
    /// Once the refcount re-read reports zero, this method must also
    /// ask whether a GC-protected artifact holds the hash — see
    /// [`BlobReclaim::ProtectedClaim`] for why such an artifact has no
    /// edge to count. The second question runs only on the path that
    /// would otherwise delete: a non-zero refcount already keeps the
    /// blob, so there is nothing left for it to decide.
    ///
    /// Returns [`BlobReclaim::Granted`] with a live guard the caller
    /// holds across
    /// [`StoragePort::delete`](super::storage::StoragePort::delete),
    /// [`BlobReclaim::Referenced`] when the hash is alive after all,
    /// [`BlobReclaim::ProtectedClaim`] when protected evidence holds it
    /// without an edge (both keeps refresh the worklist row to the
    /// observed count so the terminal `ArtifactPurged` states it), or
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

    /// Append every per-hash `ArtifactPurged` event, terminating the
    /// work item, and re-assert `artifacts.deleted_at` in one
    /// transaction. The adapter refuses the transition while any
    /// worklist row is incomplete. `events` is assembled by the
    /// application layer so attribution and event vocabulary remain
    /// orchestration policy, not adapter policy.
    ///
    /// The retirement is idempotent in the *state*: the transition
    /// succeeds whenever the row ends up retired — including when the
    /// user-facing delete path retired it first, which keeps its
    /// earlier timestamp — and reports `NotFound` only when the row is
    /// genuinely absent.
    ///
    /// By the time this runs the row is **already** retired, by
    /// [`Self::purge_artifact_refs`]. The write is kept because it is
    /// the transition's row-presence check (zero rows affected is the
    /// `NotFound`) and because the state, not the writer, is what the
    /// idempotency is about — a worklist prepared by an earlier build
    /// reaches here with `deleted_at` still unset and must still
    /// retire.
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
            _retired_at: DateTime<Utc>,
        ) -> BoxFuture<'_, DomainResult<PurgePreparation>> {
            Box::pin(async { Ok(PurgePreparation::Prepared(Vec::new())) })
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
        assert_eq!(
            p.purge_artifact_refs(Uuid::nil(), Utc::now())
                .await
                .unwrap(),
            PurgePreparation::Prepared(Vec::new())
        );
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
                _retired_at: DateTime<Utc>,
            ) -> BoxFuture<'_, DomainResult<PurgePreparation>> {
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
            p.purge_artifact_refs(Uuid::nil(), Utc::now())
                .await
                .unwrap_err(),
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

    /// The four reclamation outcomes are distinguishable and the
    /// granted one hands back a guard that releases. `Debug` is
    /// exercised on every arm: it is what a sweep's `tracing` field
    /// renders, and a guard arm that printed its transaction would put
    /// connection state in a log line.
    ///
    /// The two keeps must stay distinguishable from each other, not
    /// just from `Granted`: they report different kinds of claim and a
    /// `ProtectedClaim` rendered as `Referenced` would tell an operator
    /// to go looking for a `content_references` row that does not
    /// exist.
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

        let claimed = BlobReclaim::ProtectedClaim { claimants: 2 };
        assert_eq!(format!("{claimed:?}"), "ProtectedClaim { claimants: 2 }");
        assert!(matches!(
            claimed,
            BlobReclaim::ProtectedClaim { claimants: 2 }
        ));
        assert!(
            !matches!(
                BlobReclaim::ProtectedClaim { claimants: 2 },
                BlobReclaim::Referenced { .. }
            ),
            "a protected claim is not a reference row"
        );

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
            held_state_authorised: false,
            collection_needs_held_state_authority: false,
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

        let prep = PurgePreparation::Prepared(vec![pr.clone()]);
        assert_eq!(prep.clone(), prep);
        assert_ne!(prep, PurgePreparation::Prepared(Vec::new()));
    }

    /// The protection rules are the port's, stated once, so both
    /// readers get the same answer from the same four facts.
    #[test]
    fn the_protection_rules_are_one_predicate_each() {
        let base = PendingPurge {
            artifact_id: Uuid::new_v4(),
            quarantine_status: QuarantineStatus::Released,
            tag_targeted: false,
            expired_only_by_keep_last_n: false,
            user_deleted: false,
            held_state_authorised: false,
            collection_needs_held_state_authority: false,
        };

        // Exactly the three evidence states protect with no authority,
        // and the two serving states do not.
        for status in [
            QuarantineStatus::Quarantined,
            QuarantineStatus::Rejected,
            QuarantineStatus::ScanIndeterminate,
        ] {
            let item = PendingPurge {
                quarantine_status: status,
                ..base.clone()
            };
            assert!(
                item.is_gc_protected(),
                "{status} is retained evidence with nothing authorising its disposal"
            );
            // …and a matching held-state authority is what lifts it,
            // for each of the three states independently.
            let authorised = PendingPurge {
                quarantine_status: status,
                held_state_authorised: true,
                ..base.clone()
            };
            assert!(
                !authorised.is_gc_protected(),
                "{status} with a matching authority is collectable"
            );
        }
        for status in [QuarantineStatus::None, QuarantineStatus::Released] {
            let item = PendingPurge {
                quarantine_status: status,
                ..base.clone()
            };
            assert!(
                !item.is_gc_protected(),
                "{status} with an unconditional work item is collectable"
            );
            // …and so is one with no work item at all, which is what
            // the "only a held-state expiry" wording preserves.
            assert!(!base.is_gc_protected());
            // The one case where a serving status still refuses: the
            // artifact's only work item is a held-state expiry whose
            // occupancy has ended, which is what a curator release
            // looks like from here. Nothing authorised collecting
            // these bytes outside the state they are no longer in.
            let only_conditional = PendingPurge {
                quarantine_status: status,
                collection_needs_held_state_authority: true,
                ..base.clone()
            };
            assert!(
                only_conditional.is_gc_protected(),
                "{status} whose only work item is a lapsed held-state expiry must refuse"
            );
        }

        // The tag exemption is a conjunction of three facts, and
        // dropping any one of them changes the answer — which is what
        // keeps a reader from re-deriving two of the three.
        assert!(PendingPurge {
            tag_targeted: true,
            expired_only_by_keep_last_n: true,
            ..base.clone()
        }
        .is_tag_exempt());
        assert!(
            !PendingPurge {
                tag_targeted: false,
                expired_only_by_keep_last_n: true,
                ..base.clone()
            }
            .is_tag_exempt(),
            "no ref resolves to it"
        );
        assert!(
            !PendingPurge {
                tag_targeted: true,
                expired_only_by_keep_last_n: false,
                ..base.clone()
            }
            .is_tag_exempt(),
            "another predicate expired it, and a tag does not countermand that"
        );
        assert!(
            !PendingPurge {
                tag_targeted: true,
                expired_only_by_keep_last_n: true,
                user_deleted: true,
                ..base
            }
            .is_tag_exempt(),
            "a caller-facing delete is an explicit instruction, and \
             expired_only_by_keep_last_n is vacuous for it"
        );
    }
}
