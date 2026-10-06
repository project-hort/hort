//! `PurgeUseCase::process_expired` — the **storage-GC walk**: the
//! destructive second stage of the two-stage retention split.
//!
//! # Two-stage split
//!
//! `RetentionUseCase::evaluate_policies` is stage one — it
//! appends an [`ArtifactExpired`](hort_domain::events::ArtifactExpired)
//! to the artifact stream and deletes nothing. **This** use case is
//! stage two: for every pending **byte-release work item** with no
//! following [`ArtifactPurged`](hort_domain::events::ArtifactPurged) it
//! runs the GC algorithm (decrement `content_references`, delete the CAS
//! blob iff nothing claims it any more — no cross-`kind`
//! `content_references` row and no GC-protected artifact holding the
//! hash without one — then append all
//! `ArtifactPurged` events and retire the projection atomically). It is
//! NOT a scheduler — that is the `RetentionPurgeHandler`
//! `TaskHandler`; this is the pure orchestration the handler calls.
//!
//! # Two work items, one collector
//!
//! A byte-release work item is an `ArtifactExpired` **or** an
//! [`ArtifactDeleted`](hort_domain::events::ArtifactDeleted). A delete
//! retires an artifact from service exactly as an expiry does, and the
//! bytes it leaves behind need the same release: its
//! `content_references` source edges have to go so refcount-gated GC can
//! reach the blob. Before the delete path was admitted here it could
//! not: the edge stood forever, the refcount never fell, and no
//! predicate, policy or configuration reached those bytes.
//!
//! `ArtifactDeleted` is the carrier rather than a synthesised
//! `ArtifactExpired` (which would have to invent a `policy_id` /
//! `policy_name` and an expiry reason for a decision no policy made) and
//! rather than a new work-item event (which would duplicate, on the same
//! stream at the same instant, a fact `ArtifactDeleted` already records).
//! It is also already durable in the same transaction as
//! `artifacts.deleted_at` (`PgArtifactRepository::delete`), so the work
//! item cannot come apart from the retirement it authorises — the
//! atomicity property the terminal transition below depends on, obtained
//! without a line of new transaction code.
//!
//! A delete does **not** inherit the `KeepLastN` tag exemption: see
//! [`PendingPurge::is_tag_exempt`].
//!
//! # Reconcile-converged start-gate (binding constraint)
//!
//! The `content_references` refcount projection is **eventually
//! authoritative** (post-commit, warn-on-fail ingest/reject
//! writes). Treating a missing / decremented refcount row as
//! GC-authoritative is only safe **after a positive reconcile** — the
//! [`RefcountReconcileUseCase::sweep_drift`] convergence
//! gate, NOT a per-sweep live `NOT EXISTS` against the lagging
//! projection. This use
//! case therefore **refuses to run** unless it is constructed with a
//! [`RefcountReconcileGate`] that reports the reconcile sweep has
//! converged at least once on this deployment.
//!
//! ## The start-gate seam (BLOCK-note — read this)
//!
//! The reconcile sweep ships **no durable convergence signal**: it is a
//! boot-time sweep behind `HORT_REFCOUNT_RECONCILE_ON_STARTUP` (default
//! `true`, `crates/hort-server/src/cli/serve.rs`) and ships **no
//! migration**, so no durable "the sweep has run successfully" signal
//! is reachable from the `hort-app` layer without an out-of-scope
//! change (a durable convergence marker is sweep / scheduler /
//! composition-root territory; reading `_sqlx_migrations` needs a DSN
//! this pure-orchestration layer does not hold). The gate is therefore
//! modelled as an **injected precondition** ([`RefcountReconcileGate`])
//! the composition root satisfies — exactly the layer that already owns
//! `HORT_REFCOUNT_RECONCILE_ON_STARTUP` + the boot sweep. The
//! durable-signal wiring (a persisted "reconcile converged" marker the
//! gate reads) belongs with the `RetentionPurgeHandler` composition +
//! the worker boot path; this use case ships the gate *contract* +
//! enforcement so the invariant cannot be silently dropped.
//!
//! # GC algorithm (faithful, crash-safe)
//!
//! For each pending work item:
//! 1. Lock the artifact row `FOR UPDATE` and re-read the two
//!    protection rules under that lock
//!    ([`PendingPurge::is_gc_protected`],
//!    [`PendingPurge::is_tag_exempt`]). Either one holding stops the
//!    item here with nothing deleted — see *The page is a snapshot*
//!    below.
//! 2. Delete every `content_references` source edge for the artifact,
//!    returning each distinct target hash.
//! 3. Persist each returned hash and its post-delete count in the purge
//!    worklist, in the same transaction as the edge deletion.
//! 4. For each hash `H` the worklist recorded at count `0`, take the
//!    **hash-scoped reclamation lock** and re-ask, under it, whether
//!    anything claims `H`: the cross-kind `content_references` count
//!    (including `oci_subject` and every other kind), and — only once
//!    that count comes back `0` — whether a GC-protected artifact
//!    holds `H` without an edge. Nothing claims it ⇒
//!    `StoragePort::delete(H)` **while the lock is held**; emit no
//!    event yet. Checkpoint the successful storage decision.
//!
//!    The lock is the same one every `content_references` write takes
//!    (`blob_lock` in the Postgres adapter), and step 4 is where the
//!    artifact-vs-blob granularity mismatch is closed: steps 1-3 lock an
//!    artifact row, but what step 4 destroys is a blob, and CAS
//!    deduplicates precisely so that one blob may belong to many
//!    artifacts.
//!
//!    Three outcomes decline to delete. The lock held elsewhere is a
//!    deferral — nothing is emitted, the worklist row stands, the next
//!    sweep asks again (`blobs_deferred`). A count that is no longer
//!    zero is a *keep* — the bytes were re-claimed, the worklist row is
//!    corrected to the observed count, and the purge finishes normally
//!    with the blob intact (`blobs_kept`). A protected claimant is the
//!    same keep for a claim the count structurally cannot show (see
//!    *Evidence is never purged* below).
//! 5. Once every hash is checkpointed, append one `ArtifactPurged` per
//!    hash and set `artifacts.deleted_at` in one adapter transaction.
//!
//! Walks **both** `artifact.sha256_checksum` (`primary_content`) AND
//! `artifact_metadata.metadata_blob` (`metadata_blob`).
//!
//! ## Two-stage idempotency
//!
//! The durable `ArtifactExpired` / `ArtifactDeleted` event is the work
//! item; `ArtifactPurged` terminates it. The adapter's worklist is written atomically with the
//! reference deletion, so every hash remains discoverable after its
//! source edge is gone. A transient `StoragePort::delete` failure emits
//! no terminal event and leaves the artifact live; the next sweep reads
//! the same worklist and retries. Re-running `StoragePort::delete` on an
//! already-absent blob is a clean no-op (`delete` is
//! success-on-missing). The terminal event batch and retirement happen
//! only after every hash is complete.
//!
//! ## The page is a snapshot; the lock is where the rules decide
//!
//! Two rules keep content out of the destructive path — retained scan
//! evidence is never collected, and a `KeepLastN` tag target is exempt
//! — and both are computed from facts that move while this sweep runs:
//! a scan verdict lands, a tag is set.
//!
//! [`Self::process_one`] evaluates both rules on the **page row** it
//! was handed, and that is a pre-exit: it saves opening a transaction
//! for an artifact that is already visibly protected, and the
//! permanently-skipped prefix this sweep carries by design is exactly
//! that shape. It cannot be the interval defence. The page was read
//! before the sweep touched a single item of it, so between that read
//! and a given item's destructive step lies the complete processing of
//! every preceding item — storage deletes included. It is the longest
//! interval in the whole walk, not the shortest.
//!
//! The decision therefore sits in step 1, inside the transaction that
//! does the deleting: [`PurgeGcPort::purge_artifact_refs`] re-reads
//! the four facts under the artifact lock and answers
//! [`PurgePreparation::Protected`] / [`PurgePreparation::TagExempt`]
//! instead of preparing a worklist. Nothing is deleted on either path
//! — no edge, no byte, no event — so the work item stays pending and
//! the next sweep re-reads everything.
//!
//! The two readers are counted apart
//! ([`PurgeSummary::skipped_protected`] vs
//! [`PurgeSummary::skipped_protected_under_lock`], and likewise for
//! the tag exemption): the first is the steady state, where a
//! protected artifact is skipped on every sweep until its status or
//! tag changes, and the second is this sweep's own window closing on
//! something — a signal worth seeing rather than one to lose in the
//! first number.
//!
//! ## Evidence is never purged (defence-in-depth)
//!
//! Quarantined / rejected / scan-indeterminate artifacts are evidence
//! and must never be purged. Stage one already filters them before appending
//! `ArtifactExpired`, so a pending purge for one of them should not
//! exist; the adapter's `list_pending_purge` excludes them anyway, the
//! page-row check asserts the invariant a second time and the re-read
//! under the lock a third, rather than trusting the upstream filter (a
//! destructive item is conservative by construction).
//!
//! This holds for the delete work item too, and there stage one does
//! NOT pre-filter: an artifact is deletable whatever its quarantine
//! status (`Artifact::delete` is orthogonal to the quarantine axis), so
//! a rejected artifact really can acquire an `ArtifactDeleted`. The
//! adapter's status filter and this re-assertion are what keep its
//! evidence bytes: the row retires, the blob stays.
//!
//! ### …and protecting the artifact does not protect the bytes
//!
//! Both protections above are about the *artifact*: they keep it out of
//! the work set. Reclamation happens at the level of the **bytes**, and
//! CAS deduplicates them across artifacts, so a released sibling with
//! the same content hash carries the protected artifact's bytes into
//! step 4 while the protected artifact was never a candidate for
//! anything.
//!
//! The refcount cannot close that gap on its own: protected evidence is
//! deliberately given no `content_references` edge (the refcount repair
//! mints none, so that a repaired refcount cannot make a quarantined
//! blob look GC-protected for the wrong reason), so its claim on its
//! own hash counts zero. Step 4's second question is what closes it —
//! and because the answer is a count, the `ArtifactPurged` the sibling
//! emits carries it, so `refs_remaining > 0` still means "the blob
//! stays".

use std::sync::Arc;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use hort_domain::events::{retention_scheduler_actor, ArtifactPurged, DomainEvent, StreamId};
use hort_domain::ports::event_store::{AppendEvents, EventToAppend, ExpectedVersion};
use hort_domain::ports::purge_gc::{
    BlobReclaim, PendingPurge, PurgeGcPort, PurgePreparation, PurgedRef,
};
use hort_domain::ports::storage::StoragePort;
use hort_domain::types::ContentHash;

use crate::error::{AppError, AppResult};
use crate::metrics::{emit_retention_purged, RetentionPurgedResult};

/// Keyset page size for the pending-purge walk. Mirrors
/// [`RetentionEvaluateHandler`](crate::task_handlers::retention_evaluate)'s
/// `BATCH_SIZE`: one page is fetched, processed, and dropped before the
/// next is asked for, so a backlog of any size costs one page of memory.
pub(crate) const BATCH_SIZE: u32 = 1000;

/// Per-run page cap — at most `MAX_BATCHES_PER_TICK * BATCH_SIZE`
/// artifacts per sweep, the same shape and the same numbers as
/// retention-evaluate's.
///
/// The first sweep after a deployment faces the entire accumulated
/// backlog, and the set's size is only known once it is fully loaded —
/// which is the one thing an unbounded walk cannot find out in advance.
/// Capping it fits the posture this sweep already has: byte reclamation
/// is housekeeping, and a run that leaves work for the next run has
/// deferred nothing that matters.
///
/// **No cursor, unlike retention-evaluate.** Its candidates stay
/// candidates, so without a persisted resume point everything past the
/// first page would be re-examined forever. This sweep *consumes* its
/// work set — a processed artifact gains an `ArtifactPurged` and leaves
/// the set — so the next run starts where this one effectively stopped.
/// The exception is the permanently-skipped prefix (tag-exempt and
/// evidence-protected artifacts, which stay pending by design): they
/// occupy the head of every run's first pages, and a prefix of them
/// larger than the whole cap would starve the work behind it. At 64 000
/// that is not a reachable shape, and it is visible when it happens —
/// `skipped_tag_exempt` + `skipped_protected` summing to the cap with
/// `artifacts_visited` pinned there is exactly what it looks like.
pub(crate) const MAX_BATCHES_PER_TICK: usize = 64;

/// Reports whether the refcount-reconcile sweep
/// ([`RefcountReconcileUseCase::sweep_drift`](super::refcount_reconcile_use_case::RefcountReconcileUseCase))
/// has converged at least once on this deployment.
///
/// **Why an injected gate and not a direct signal read.** The sweep
/// leaves no durable convergence marker (see this module's "start-gate
/// seam" BLOCK-note) and the durable-signal mechanism is not reachable
/// from this pure-orchestration layer without an out-of-scope change.
/// The gate is therefore satisfied by the composition root — the layer
/// that already owns `HORT_REFCOUNT_RECONCILE_ON_STARTUP` and runs the
/// boot sweep. The contract: `is_converged()` returns `true` **only**
/// once a reconcile sweep has *converged* on this deployment — which is
/// [`ReconcileSummary::converged`](super::refcount_reconcile_use_case::ReconcileSummary::converged),
/// not the `Ok`-ness of `sweep_drift`. The sweep keeps going past a
/// failing repository and still returns `Ok`, so a composition root
/// that reads `Ok` as convergence opens this gate over a projection
/// that may still be missing edges.
pub trait RefcountReconcileGate: Send + Sync {
    /// `true` iff the reconcile sweep (`RefcountReconcileUseCase::sweep_drift`) has
    /// converged at least once on this deployment — a pass that swept
    /// every repository and applied every repair with **zero**
    /// recorded failures. A partially-failed pass is not convergence.
    /// While `false`, the
    /// refcount projection may be drifted and no GC consumer may treat
    /// a decremented / missing refcount row as authoritative — the
    /// purge sweep refuses to run.
    fn is_converged(&self) -> bool;
}

/// Outcome summary of one `process_expired` pass — the
/// `result_summary` JSON shape the `RetentionPurgeHandler` `TaskHandler`
/// surfaces.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PurgeSummary {
    /// Pending `ArtifactExpired` artifacts the sweep visited.
    pub artifacts_visited: u64,
    /// CAS blobs deleted (nothing claimed the hash under the lock).
    pub blobs_deleted: u64,
    /// References removed whose blob stays, because a claim on the
    /// hash held under the lock: a live `content_references` row, or a
    /// GC-protected artifact that holds the bytes without one.
    pub blobs_kept: u64,
    /// Unclaimed blobs left standing because the hash-scoped
    /// reclamation lock was held by someone else — a concurrent
    /// reference write on exactly these bytes, or a second sweep. No
    /// terminal event was emitted and the worklist row is retained, so
    /// the next run asks again.
    ///
    /// This is the field that tells "nothing to reclaim" apart from
    /// "reclamation is being skipped": the first is
    /// `artifacts_visited = 0`, the second is `artifacts_visited > 0`
    /// with `blobs_deferred > 0` and `purged_events` short of it, run
    /// after run.
    pub blobs_deferred: u64,
    /// `ArtifactPurged` events appended (one per processed hash).
    pub purged_events: u64,
    /// Artifacts the page row already showed as GC-protected evidence
    /// — the pre-exit, before the artifact lock was taken. This is the
    /// steady-state number: a protected artifact stays in the pending
    /// set and is skipped on every sweep until its status changes.
    pub skipped_protected: u64,
    /// Artifacts the page row already showed as tag-exempt
    /// ([`PendingPurge::is_tag_exempt`]) — the pre-exit, and the
    /// steady-state number for the same reason as
    /// [`Self::skipped_protected`].
    pub skipped_tag_exempt: u64,
    /// Artifacts refused by the **re-read under the artifact lock**
    /// because they had become GC-protected evidence since the page
    /// row was taken. Disjoint from [`Self::skipped_protected`]: this
    /// one counts a scan verdict landing inside the sweep's own window,
    /// which is a far rarer and far more interesting event than a
    /// protected artifact being skipped again.
    ///
    /// Nothing was deleted for these artifacts — no edge, no byte, no
    /// event — and the work item is still pending.
    pub skipped_protected_under_lock: u64,
    /// Artifacts refused by the re-read under the artifact lock because
    /// a mutable ref came to resolve to them since the page row was
    /// taken. Disjoint from [`Self::skipped_tag_exempt`], same
    /// reasoning as the field above.
    pub skipped_tag_exempt_under_lock: u64,
    /// Visited artifacts whose work item was a caller-facing delete
    /// (`ArtifactDeleted`) rather than a policy expiry. Reported because
    /// this sweep collects both and a deployment with no retention
    /// policy configured at all still has blobs to reclaim here —
    /// without the split, `blobs_deleted` moving would be unattributable.
    pub user_deletes_visited: u64,
    /// Per-artifact failures (prepare / storage / checkpoint / terminal
    /// transition).
    /// The `ArtifactExpired` decision is retained; next sweep retries.
    pub errors: u64,
}

/// The storage-GC walk. Pure orchestration over the
/// additive [`PurgeGcPort`], the existing [`StoragePort`], and the
/// event store. Refuses to run unless the [`RefcountReconcileGate`]
/// reports the refcount-reconcile sweep has converged.
pub struct PurgeUseCase {
    gc: Arc<dyn PurgeGcPort>,
    storage: Arc<dyn StoragePort>,
    reconcile_gate: Arc<dyn RefcountReconcileGate>,
    /// Keyset page size. Defaults to [`BATCH_SIZE`]; a field rather
    /// than a bare const read so the page boundary is unit-testable
    /// without a 1000-row fixture. Mirrors
    /// [`RetentionEvaluateHandler`](crate::task_handlers::retention_evaluate)'s
    /// field of the same name.
    batch_size: u32,
    /// Per-run page cap. Defaults to [`MAX_BATCHES_PER_TICK`]; a field
    /// for the same reason as [`Self::batch_size`] — reaching the cap
    /// is what makes a run stop short, and a 64 000-row fixture is not
    /// how that should be proven.
    max_batches_per_tick: usize,
}

impl PurgeUseCase {
    /// Construct the use case. `reconcile_gate` is the reconcile-converged
    /// start-gate (see the module BLOCK-note); the composition root
    /// supplies an implementation that is `true` only after a reconcile
    /// sweep converged on this deployment.
    pub fn new(
        gc: Arc<dyn PurgeGcPort>,
        storage: Arc<dyn StoragePort>,
        reconcile_gate: Arc<dyn RefcountReconcileGate>,
    ) -> Self {
        Self {
            gc,
            storage,
            reconcile_gate,
            batch_size: BATCH_SIZE,
            max_batches_per_tick: MAX_BATCHES_PER_TICK,
        }
    }

    /// Run the storage-GC walk for every pending `ArtifactExpired`
    /// at wall-clock `now` (`now` is injected so it is coherent across
    /// retries and pinnable in tests — the retention-sweep convention).
    ///
    /// **Refuses to run** (returns `AppError::Domain` /
    /// `DomainError::Invariant`) when the [`RefcountReconcileGate`]
    /// reports the reconcile sweep has not converged — the binding
    /// constraint: no GC consumer may read the eventually-authoritative
    /// refcount projection until the reconcile gate is satisfied.
    ///
    /// One bad artifact (port / storage / append failure) is recorded
    /// in [`PurgeSummary::errors`] and the sweep continues — the
    /// `ArtifactExpired` decision is retained and the next sweep
    /// retries (per-artifact, not fatal).
    #[tracing::instrument(skip(self))]
    pub async fn process_expired(&self, now: DateTime<Utc>) -> AppResult<PurgeSummary> {
        // -- reconcile-converged start-gate (binding constraint) ----------
        if !self.reconcile_gate.is_converged() {
            tracing::warn!(
                "PurgeUseCase refused to run: the refcount-reconcile sweep \
                 has not converged on this deployment. The content_references \
                 refcount projection is eventually authoritative; a GC walk \
                 over a pre-reconcile projection could delete a live blob. \
                 Run the refcount-reconcile sweep to convergence first."
            );
            return Err(AppError::Domain(
                hort_domain::error::DomainError::Invariant(
                    "PurgeUseCase start-gate: RefcountReconcileUseCase \
                 has not converged; storage GC is refused (reconcile-converged \
                 binding constraint)"
                        .to_owned(),
                ),
            ));
        }

        tracing::info!(
            batch_size = self.batch_size,
            max_batches_per_tick = self.max_batches_per_tick,
            "storage-GC purge sweep starting (reconcile-converged gate satisfied)"
        );

        // Keyset walk, capped at `MAX_BATCHES_PER_TICK` pages. The
        // cursor advances over every row the page returned — including
        // the ones this sweep declines to act on — so a permanently
        // skipped artifact is passed, not re-read until the cap.
        let mut summary = PurgeSummary::default();
        let mut after: Option<Uuid> = None;
        for _ in 0..self.max_batches_per_tick {
            let page = self
                .gc
                .list_pending_purge(self.batch_size, after)
                .await
                .map_err(AppError::Domain)?;
            let Some(last) = page.last() else {
                break;
            };
            after = Some(last.artifact_id);
            let full_page = page.len() as u32 >= self.batch_size;

            for item in &page {
                summary.artifacts_visited += 1;
                if item.user_deleted {
                    summary.user_deletes_visited += 1;
                }
                self.process_one(now, item, &mut summary).await;
            }

            if !full_page {
                break;
            }
        }

        tracing::info!(
            artifacts_visited = summary.artifacts_visited,
            blobs_deleted = summary.blobs_deleted,
            blobs_kept = summary.blobs_kept,
            blobs_deferred = summary.blobs_deferred,
            purged_events = summary.purged_events,
            skipped_protected = summary.skipped_protected,
            skipped_tag_exempt = summary.skipped_tag_exempt,
            skipped_protected_under_lock = summary.skipped_protected_under_lock,
            skipped_tag_exempt_under_lock = summary.skipped_tag_exempt_under_lock,
            user_deletes_visited = summary.user_deletes_visited,
            errors = summary.errors,
            "storage-GC purge sweep complete"
        );
        Ok(summary)
    }

    /// Process one pending-purge artifact. Isolated so any failure maps
    /// to a [`PurgeSummary::errors`] increment and the sweep continues.
    async fn process_one(
        &self,
        now: DateTime<Utc>,
        item: &PendingPurge,
        summary: &mut PurgeSummary,
    ) {
        // -- cheap pre-exits over the page row ---------------------------
        //
        // Both protection rules are re-read under the artifact lock by
        // `purge_artifact_refs`, which is where the decision is
        // actually taken (see the match on its outcome below). What
        // these two checks buy is the lock: an artifact that is already
        // visibly protected on the page row is skipped without opening
        // a transaction for it, and the permanently-skipped prefix this
        // sweep carries by design is exactly that shape.
        //
        // They are not the interval defence and must not be read as
        // one. `item` is the page row, and between it and *this*
        // artifact's destructive step lies the complete processing of
        // every preceding item of the page, storage deletes included.
        if item.is_gc_protected() {
            summary.skipped_protected += 1;
            tracing::warn!(
                artifact_id = %item.artifact_id,
                status = %item.quarantine_status,
                "inv1: pending-purge artifact is quarantined/rejected/\
                 indeterminate (evidence) — skipped, NOT purged. This \
                 should have been filtered before ArtifactExpired; \
                 re-asserted here because purge is destructive."
            );
            return;
        }

        if item.is_tag_exempt() {
            summary.skipped_tag_exempt += 1;
            tracing::info!(
                artifact_id = %item.artifact_id,
                "a mutable ref in this artifact's repository resolves to it, \
                 every pending expiry was KeepLastN and no delete was \
                 requested — tag exemption asserted on the page row, NOT \
                 purged. The ArtifactExpired is retained; the artifact is \
                 purged once the tag moves."
            );
            return;
        }

        // -- durable worklist preparation (committed, idempotent) --------
        //
        // Both protection rules are re-read here under the artifact
        // lock, in the transaction that deletes the edges, and a
        // refusal arrives as its own outcome rather than as an empty
        // worklist — the three non-`Prepared` answers mean different
        // things and are counted and logged apart.
        let prepared = match self.gc.purge_artifact_refs(item.artifact_id).await {
            Ok(r) => r,
            Err(e) => {
                summary.errors += 1;
                tracing::error!(
                    artifact_id = %item.artifact_id,
                    error = %e,
                    "purge_artifact_refs failed — ArtifactExpired retained, \
                     retried on next sweep"
                );
                return;
            }
        };

        let mut purged_refs = match prepared {
            PurgePreparation::Prepared(refs) => refs,
            PurgePreparation::Protected { status } => {
                // The page row said this artifact was collectable and
                // the read under the lock disagreed: a scan verdict
                // landed while the sweep worked through the items
                // before it. Nothing was deleted.
                summary.skipped_protected_under_lock += 1;
                tracing::warn!(
                    artifact_id = %item.artifact_id,
                    status = %status,
                    page_status = %item.quarantine_status,
                    "the artifact became GC-protected evidence after this \
                     sweep read its page row — refused under the artifact \
                     lock, nothing deleted. No edge, no byte and no event; \
                     the work item stays pending and the next sweep \
                     re-reads it."
                );
                return;
            }
            PurgePreparation::TagExempt => {
                // Same shape, the other rule: a mutable ref landed on a
                // KeepLastN target inside this sweep's own window.
                summary.skipped_tag_exempt_under_lock += 1;
                tracing::info!(
                    artifact_id = %item.artifact_id,
                    "a mutable ref came to resolve to this artifact after \
                     this sweep read its page row — tag exemption applied \
                     under the artifact lock, nothing deleted. The \
                     ArtifactExpired is retained; the artifact is purged \
                     once the tag moves."
                );
                return;
            }
            PurgePreparation::NoArtifact => {
                // The row the page offered is gone — a repository
                // hard-delete cascade, since the artifact verbs only
                // ever soft-delete. Nothing was locked, read or
                // deleted, there are no bytes left to release through
                // it, and it will not be offered again. Distinct from
                // the two refusals above on purpose: those are
                // protections holding, this is work that evaporated.
                tracing::warn!(
                    artifact_id = %item.artifact_id,
                    "the artifact row vanished between the page read and \
                     the purge preparation — nothing to release, work item \
                     dropped with it"
                );
                return;
            }
        };

        // A port that hands back an empty worklist has nothing to
        // checkpoint and nothing to emit; `NoArtifact` is the answer
        // for the case this used to stand in for.
        if purged_refs.is_empty() {
            return;
        }

        for pr in &mut purged_refs {
            if pr.completed {
                continue;
            }
            if !self
                .finish_one_ref(now, item.artifact_id, pr, summary)
                .await
            {
                return;
            }
        }

        let events = purged_refs
            .iter()
            .map(|pr| {
                EventToAppend::new(DomainEvent::ArtifactPurged(ArtifactPurged {
                    artifact_id: item.artifact_id,
                    content_hash: pr.content_hash.clone(),
                    refs_remaining: pr.refs_remaining,
                    purged_at: now,
                }))
            })
            .collect();
        let event_count = purged_refs.len() as u64;
        let batch = AppendEvents {
            stream_id: StreamId::artifact(item.artifact_id),
            expected_version: ExpectedVersion::Any,
            events,
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: retention_scheduler_actor(),
        };

        match self
            .gc
            .complete_artifact_purge(item.artifact_id, now, batch)
            .await
        {
            Ok(()) => {
                summary.purged_events += event_count;
                for pr in &purged_refs {
                    if pr.refs_remaining == 0 {
                        emit_retention_purged(RetentionPurgedResult::Success);
                    } else {
                        emit_retention_purged(RetentionPurgedResult::BlobKept);
                    }
                }
                tracing::info!(
                    artifact_id = %item.artifact_id,
                    purged_events = event_count,
                    "artifact purge completed and projection retired"
                );
            }
            Err(e) => {
                summary.errors += 1;
                tracing::error!(
                    artifact_id = %item.artifact_id,
                    error = %e,
                    "atomic ArtifactPurged append and projection retirement failed — \
                     worklist retained, retried on next sweep"
                );
            }
        }
    }

    /// Execute the storage decision for one hash, then checkpoint it.
    /// A transient `StoragePort::delete` failure leaves the checkpoint
    /// outstanding and emits no terminal event, so the next sweep
    /// retries from the durable worklist.
    ///
    /// # The lock, and why the delete happens underneath it
    ///
    /// `pr.refs_remaining` came from the worklist, which was written by
    /// a transaction that committed before this method was ever called
    /// — on a retry, possibly in a previous sweep on a previous day. It
    /// is a snapshot of a count, and a snapshot is not permission to
    /// destroy anything: CAS shares a hash across every artifact that
    /// carries those bytes, so the artifact-row lock the preparation
    /// held says nothing about the blob.
    ///
    /// So the count is re-read under a **hash-scoped** lock
    /// ([`PurgeGcPort::begin_blob_reclaim`]) and the delete happens
    /// while that lock is still held. Every path that records a
    /// `content_references` row takes the same lock, which is what
    /// makes the re-read conclusive: a concurrent claim on these bytes
    /// is either already committed — and counted — or blocked until the
    /// lease ends, by which time the answer it will get from CAS is the
    /// truth.
    ///
    /// Three of the four outcomes decline to delete, and that is the
    /// design. Reclaiming storage is housekeeping the human's event
    /// model explicitly detached from external behaviour; being wrong
    /// once about a live blob is not recoverable, and being late is.
    ///
    /// # The claim the refcount cannot see
    ///
    /// A `content_references` row is not the only hold on a blob. An
    /// artifact in a GC-protected quarantine state is retained scan
    /// evidence, and the refcount repair deliberately mints no edge for
    /// it — so its claim on its own bytes counts zero, while CAS shares
    /// those bytes with every sibling of the same content. The lease
    /// therefore also answers
    /// [`BlobReclaim::ProtectedClaim`](hort_domain::ports::purge_gc::BlobReclaim::ProtectedClaim),
    /// which this method treats exactly like `Referenced`: a keep, not
    /// a deferral.
    async fn finish_one_ref(
        &self,
        now: DateTime<Utc>,
        artifact_id: Uuid,
        pr: &mut PurgedRef,
        summary: &mut PurgeSummary,
    ) -> bool {
        let hash_short = truncate_hash(&pr.content_hash);

        if pr.refs_remaining == 0 {
            let lease = match self
                .gc
                .begin_blob_reclaim(artifact_id, &pr.content_hash)
                .await
            {
                Ok(lease) => lease,
                Err(e) => {
                    summary.errors += 1;
                    tracing::error!(
                        %artifact_id,
                        content_hash = %hash_short,
                        error = %e,
                        "blob-reclamation lease failed — no delete attempted, \
                         worklist retained, retried on next sweep"
                    );
                    return false;
                }
            };

            match lease {
                BlobReclaim::Contended => {
                    summary.blobs_deferred += 1;
                    emit_retention_purged(RetentionPurgedResult::Deferred);
                    tracing::info!(
                        %artifact_id,
                        content_hash = %hash_short,
                        "blob-reclamation lock held elsewhere — a reference \
                         to these bytes is being written right now, or a \
                         second sweep is already on them. Nothing deleted, \
                         worklist row retained, retried on next sweep."
                    );
                    return false;
                }
                BlobReclaim::Referenced { refs_now } => {
                    // The worklist's zero was stale: these bytes are
                    // claimed again. Adopt the count that actually held
                    // so the `ArtifactPurged` below states it, and fall
                    // through to the checkpoint — this is a blob kept,
                    // not a deferral. Re-asking forever would leave the
                    // artifact's purge permanently unfinishable, and
                    // there is nothing left to wait for: a committed
                    // reference is a live reference.
                    tracing::info!(
                        %artifact_id,
                        content_hash = %hash_short,
                        refs_now,
                        "the worklist's refcount-0 decision was superseded — \
                         these bytes were re-referenced since it was taken. \
                         Blob kept; ArtifactPurged carries the observed count."
                    );
                    pr.refs_remaining = refs_now;
                }
                BlobReclaim::ProtectedClaim { claimants } => {
                    // The refcount was genuinely zero and these bytes
                    // are still held: a quarantined / rejected /
                    // scan_indeterminate artifact carries this hash as
                    // its primary content or its metadata blob, and
                    // protected evidence is deliberately given no
                    // reference edge to count. Keep the blob and state
                    // the claim count, same as the branch above — and
                    // terminal for a stronger reason: a rejected
                    // artifact is permanent, so re-asking would never
                    // get a different answer and this sibling's purge
                    // would never finish.
                    tracing::info!(
                        %artifact_id,
                        content_hash = %hash_short,
                        claimants,
                        "the bytes are claimed by GC-protected evidence that \
                         holds no reference edge — refcount 0 was true and \
                         not the whole answer. Blob kept; ArtifactPurged \
                         carries the claim count."
                    );
                    pr.refs_remaining = claimants;
                }
                BlobReclaim::Granted(guard) => {
                    // GC-eligible and still so under the lock: delete
                    // the CAS blob. `delete` is success-on-missing: the
                    // adapter MAY surface an already-absent blob as
                    // `Ok(())` OR as `DomainError::NotFound`
                    // (StoragePort doc contract). Both mean "the blob is
                    // gone" and are the correct idempotent outcome on a
                    // retry — only a NON-`NotFound` error is the
                    // transient failure that must NOT lose the decision.
                    let deleted = self.storage.delete(&pr.content_hash).await;

                    // Release on every path, before classifying the
                    // delete: an early `return` between the delete and
                    // the release would hold a pooled connection's
                    // transaction open for as long as the error path
                    // took.
                    if let Err(e) = guard.release().await {
                        tracing::warn!(
                            %artifact_id,
                            content_hash = %hash_short,
                            error = %e,
                            "releasing the blob-reclamation lease failed; the \
                             lock ends with the transaction regardless"
                        );
                    }

                    match deleted {
                        Ok(()) => {}
                        Err(hort_domain::error::DomainError::NotFound { .. }) => {
                            tracing::info!(
                                %artifact_id,
                                content_hash = %hash_short,
                                "blob already absent on delete — \
                                 success-on-missing (idempotent re-purge)"
                            );
                        }
                        Err(e) => {
                            summary.errors += 1;
                            emit_retention_purged(RetentionPurgedResult::StorageError);
                            tracing::warn!(
                                %artifact_id,
                                content_hash = %hash_short,
                                error = %e,
                                "storage delete failed for a refcount-0 blob — \
                                 ArtifactExpired retained (no ArtifactPurged \
                                 emitted), retried on next sweep (two-stage \
                                 idempotency)"
                            );
                            return false;
                        }
                    }
                }
            }
        }

        match self
            .gc
            .mark_purge_ref_complete(artifact_id, &pr.content_hash, now)
            .await
        {
            Ok(()) => {
                if pr.refs_remaining == 0 {
                    summary.blobs_deleted += 1;
                } else {
                    summary.blobs_kept += 1;
                }
                true
            }
            Err(e) => {
                summary.errors += 1;
                tracing::error!(
                    %artifact_id,
                    content_hash = %hash_short,
                    error = %e,
                    "purge worklist checkpoint failed after storage step — \
                     terminal transition withheld, retried on next sweep"
                );
                false
            }
        }
    }
}

/// `tracing`-only truncation of a content hash (first 12 hex chars) —
/// the "content_hash (truncated)" tracing convention. Never a
/// metric label (cardinality hard-block).
fn truncate_hash(h: &ContentHash) -> String {
    let s = h.as_ref();
    s.chars().take(12).collect()
}

#[cfg(test)]
#[path = "purge_use_case_tests.rs"]
mod tests;
