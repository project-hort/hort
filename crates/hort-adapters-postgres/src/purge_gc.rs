//! PostgreSQL adapter for [`PurgeGcPort`] — the storage-GC walk
//! (`PurgeUseCase::process_expired`). The port module docs
//! (`hort-domain/src/ports/purge_gc.rs`) carry the design this
//! implements; the algorithm's own steps are numbered below.
//!
//! Runs the refcount-GC algorithm against the eventually-authoritative
//! `content_references` refcount projection (safe only behind the
//! `RefcountReconcileUseCase` convergence gate the use case
//! enforces — see the port module docs
//! (`hort-domain/src/ports/purge_gc.rs`) for the posture this consumes).
//!
//! # `list_pending_purge`
//!
//! Every artifact whose stream (`stream_id = 'artifact-' || a.id`)
//! carries a **byte-release work item** — an `ArtifactExpired` (a
//! retention policy decided) or an `ArtifactDeleted` (a caller deleted
//! it through the registry API) — and **no** `ArtifactPurged` event:
//! the pending purge work set. `quarantine_status ∈ {quarantined,
//! rejected, scan_indeterminate}` is excluded (evidence is
//! GC-protected); the use case re-asserts the same invariant
//! defence-in-depth, but the adapter never hands a protected artifact
//! to the destructive path in the first place.
//!
//! Both work items retire an artifact from service and both must
//! release its `content_references` source edges; there is deliberately
//! one destructive sweep rather than two, so the durable worklist and
//! the atomic terminal transition below are earned once. A delete needs
//! no expiry decision synthesised for it: `ArtifactDeleted` already
//! commits in the same transaction as `artifacts.deleted_at`
//! (`artifact_repo::delete`), which is exactly the durability the
//! terminal transition depends on.
//!
//! ## The three reported facts
//!
//! The query also reports, per row, the facts the `KeepLastN` tag
//! exemption needs at purge time. They are reported rather than
//! filtered: the *decision* lives in the use case, where it lands in
//! the sweep summary instead of disappearing into a `WHERE` clause.
//!
//! - `tag_targeted` — a mutable ref **in the artifact's own
//!   repository** currently resolves to it: `target_kind = 'hash'`
//!   against `checksum_sha256` (the OCI tag) or
//!   `target_kind = 'version'` against `(namespace, version)` (the npm
//!   dist-tag shape). The repository scope matters because CAS shares
//!   content hashes across repositories; the version arm matters
//!   because a hash-only reading protects nothing outside OCI; the
//!   `namespace` conjunct matters because otherwise one package's
//!   `latest` would exempt every same-versioned package beside it.
//!   This is read at sweep time, not inherited from the evaluation
//!   sweep: the two sweeps are an hour apart and a tag set in between
//!   arrives after the `ArtifactExpired` is already on the stream. It
//!   is nonetheless a page snapshot — `purge_artifact_refs` reads the
//!   same predicate again under the artifact lock, and that reading is
//!   the one the destructive step turns on.
//! - `expired_only_by_keep_last_n` — no pending `ArtifactExpired` on
//!   the stream carries a readable non-`KeepLastN` reason; the
//!   exemption belongs to `KeepLastN` alone, because an age- or
//!   security-driven decision is not countermanded by a tag. See
//!   `ARTIFACT_EXPIRED_ONLY_BY_KEEP_LAST_N_SQL` for the predicate and
//!   its fail-safe direction.
//! - `user_deleted` — an `ArtifactDeleted` is on the stream. A
//!   delete-driven work item must not inherit the `KeepLastN` tag
//!   exemption (a delete is the caller's explicit instruction, like an
//!   age- or security-driven policy), and `expired_only_by_keep_last_n`
//!   is vacuously true for an artifact with no expiry decision at all —
//!   so the exemption needs this second fact to stay scoped to
//!   `KeepLastN`. The two facts stay separate columns because the use
//!   case composes them; collapsing them here would move the decision
//!   into the `WHERE` clause the previous paragraph keeps it out of.
//!
//! # `purge_artifact_refs` — durable preparation in one transaction
//!
//! 1. `SELECT … FROM artifacts WHERE id = $1 FOR UPDATE` — lock the
//!    artifact row so a concurrent ingest/promote cannot race the
//!    refcount decrement; also recovers the authoritative
//!    `checksum_sha256` for the idempotent-retry path. This lock is
//!    about *this artifact's* bookkeeping and says nothing about the
//!    blobs it points at — see `begin_blob_reclaim` below, which is the
//!    lock the destructive step runs under.
//!
//!    The same statement reads the four protection facts
//!    (`quarantine_status`, `tag_targeted`,
//!    `expired_only_by_keep_last_n`, `user_deleted`), and the two port
//!    predicates (`PendingPurge::is_gc_protected` /
//!    `::is_tag_exempt`) are applied to them. Either one holding ends
//!    the transaction here — `PurgePreparation::Protected` /
//!    `::TagExempt`, no `DELETE`, no worklist row, no event, work item
//!    still pending.
//!
//!    This is where the protection decision belongs, because step 2 is
//!    the first irreversible one and the facts move while the sweep
//!    runs. It is also why the retirement in step 2 sits *after* this
//!    read: a refusal must leave the artifact in service. The caller
//!    checks the same two rules on its page row
//!    first, which saves taking this lock in the ordinary case and is
//!    the whole of what it does: between that page read and *this*
//!    artifact's step 2 lies the complete processing of every
//!    preceding item of the page, storage deletes included. Same
//!    division of labour as `mutable_refs`'s `set` — the
//!    in-transaction `FOR UPDATE` re-read is the race defence, the
//!    earlier read is the optimisation.
//! 2. `UPDATE artifacts SET deleted_at = COALESCE(deleted_at, $2)` —
//!    retire the projection, in this same transaction and ahead of the
//!    statement below. `deleted_at` is the fact that takes the artifact
//!    out of service, so it is durable before the first byte can go
//!    missing underneath it; `COALESCE` keeps a caller-facing delete's
//!    earlier timestamp. See the port's `purge_artifact_refs` docs for
//!    the window this closes and why an aborted run's
//!    retired-with-intact-bytes state is the safe one. Then
//!    `DELETE FROM content_references WHERE source_artifact_id = $1
//!    RETURNING target_content_hash` — remove **every** kind of this
//!    artifact's own source-edges: the `primary_content` /
//!    `metadata_blob` refcount rows and any `oci_index_member` /
//!    `oci_subject` / `oci_config` / `oci_layer` membership edges this
//!    artifact carries as a source. The retained audit row means the
//!    FK's `ON DELETE CASCADE` never fires for a purge, so this explicit
//!    DELETE is the only sweep that reaches those membership edges. Mirrors
//!    `pg_content_reference_repo::delete_by_source`'s all-kinds
//!    behavior (the manifest-DELETE path), now applied to purge too.
//! 3. For each distinct returned hash `H`:
//!    `SELECT count(*) FROM content_references WHERE
//!    target_content_hash = H` — the **cross-`kind`** remaining count
//!    (covers `oci_subject` / `oci_index_member` / `oci_config` /
//!    `oci_layer` too: a live OCI manifest/index still pointing at `H`
//!    keeps the blob alive even when the artifact whose primary content
//!    matches `H` is purged).
//! 4. Insert every `(artifact, hash, refs_remaining)` decision into
//!    `artifact_purge_worklist` before committing. Retries read this
//!    table rather than trying to reconstruct targets from deleted
//!    edges, so every OCI target remains actionable.
//!
//! ## `begin_blob_reclaim` — the lock the delete happens under
//!
//! Steps 1-4 above lock an **artifact row**. What the sweep destroys is
//! a **blob**, and CAS deduplicates precisely so that one blob may
//! belong to many artifacts — so that lock is the wrong granularity for
//! the destructive decision, and the `refs_remaining` it produced is a
//! snapshot of a count that the delete may act on sweeps later.
//!
//! `begin_blob_reclaim` is where that is corrected: it takes the
//! hash-scoped [`blob_lock`](crate::blob_lock) with `try` (never
//! waiting — see that module) and re-reads the cross-`kind` count under
//! it. Non-zero ⇒ `Referenced`, with the worklist row corrected in
//! place so the terminal event states the count that held. Lock busy ⇒
//! `Contended`, and nothing is read or changed.
//!
//! Every production `content_references` write takes the same lock
//! (`pg_content_reference_repo::insert`, `refcount_reconcile`'s repair
//! upsert), which is what makes the re-read conclusive rather than just
//! fresher.
//!
//! ### Zero references is not the same as nothing claiming the bytes
//!
//! A refcount of zero authorises the delete only once the second
//! question has been asked: does a non-deleted **GC-protected**
//! artifact hold this hash? `refcount_reconcile` deliberately mints no
//! `content_references` edge for `quarantined` / `rejected` /
//! `scan_indeterminate` artifacts, so such an artifact's claim on its
//! own bytes counts zero and will keep counting zero. The two
//! protections that exist — `list_pending_purge` never offering it,
//! `retention_candidate_reader` never expiring it — keep the
//! *artifact* out of the sweeps; the reclamation decision is about the
//! *bytes*, which CAS shares with every artifact of the same content.
//! Without the second question a released sibling's purge deletes
//! retained evidence whose artifact was never a candidate for
//! anything. So: zero refs **and** zero protected claimants ⇒
//! `Granted`, a guard the caller holds across `StoragePort::delete`;
//! zero refs with claimants ⇒ `ProtectedClaim`, the worklist row
//! corrected to the claimant count exactly as the `Referenced` path
//! corrects it. `protected_claimants` carries the query and the
//! reasoning.
//!
//! After storage decisions have been checkpointed per worklist row,
//! `complete_artifact_purge` appends the whole per-hash terminal event
//! batch in one transaction, terminating the work item. It re-asserts
//! `artifacts.deleted_at` there too, which is a no-op on the normal
//! path (step 2 wrote it) and is kept as the transition's
//! row-presence check plus the retirement for a worklist prepared by a
//! build that retired only at the end.
//!
//! `metadata_blob` is stored as `character(64)` (blank-padded) on
//! `artifact_metadata`; it is trimmed at the boundary before parsing,
//! mirroring `pg_content_reference_repo::row_to_reference` /
//! `refcount_reconcile::parse_hash`.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;

#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};

use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::events::{DomainEvent, StreamId};
use hort_domain::ports::event_store::AppendEvents;
use hort_domain::ports::purge_gc::{
    BlobReclaim, BlobReclaimGuard, PendingPurge, PurgeGcPort, PurgePreparation, PurgedRef,
};
use hort_domain::types::ContentHash;

use crate::event_store::PgEventStore;
use crate::{map_sqlx_error, BoxFuture};

/// PostgreSQL implementation of [`PurgeGcPort`].
///
pub struct PgPurgeGcPort {
    pool: PgPool,
    event_store: Arc<PgEventStore>,
    #[cfg(test)]
    interrupt_after_append: AtomicBool,
}

impl PgPurgeGcPort {
    pub fn new(pool: PgPool, event_store: Arc<PgEventStore>) -> Self {
        Self {
            pool,
            event_store,
            #[cfg(test)]
            interrupt_after_append: AtomicBool::new(false),
        }
    }

    #[cfg(test)]
    fn interrupt_next_terminal_transition(&self) {
        self.interrupt_after_append.store(true, Ordering::SeqCst);
    }
}

/// One pending-purge artifact: it carries a byte-release work item
/// (`ArtifactExpired` or `ArtifactDeleted`) with no following
/// `ArtifactPurged`, and is not in a GC-protected quarantine state.
#[derive(Debug, FromRow)]
struct PendingRow {
    artifact_id: Uuid,
    quarantine_status: Option<String>,
    tag_targeted: bool,
    expired_only_by_keep_last_n: bool,
    user_deleted: bool,
}

/// SQL for `expired_only_by_keep_last_n`: no pending `ArtifactExpired`
/// on the artifact's stream carries a readable **non**-`KeepLastN`
/// reason. Expects the artifacts row in scope as `a`; binds nothing.
///
/// `ExpirationReason` is an externally-tagged enum, so a count-based
/// expiry stores `{"KeepLastN": {…}}` under
/// `event_data->'data'->'reason'`.
///
/// The `jsonb_typeof(…) = 'object'` guard is the fail-safe direction:
/// only a payload that positively reads as *some other* reason clears
/// the exemption. An absent or non-object reason leaves the flag set,
/// which at worst withholds a destructive step on an artifact a tag
/// currently names — visible in the sweep summary and released as soon
/// as the tag moves. The opposite default would let an unreadable
/// payload delete content a live tag resolves to, and deletion does
/// not come back.
///
/// One string because two readers ask: the page query and the re-read
/// under the artifact lock. Two spellings of a fail-safe predicate is
/// one spelling that is fail-safe and one that was, once.
const ARTIFACT_EXPIRED_ONLY_BY_KEEP_LAST_N_SQL: &str = r#"
    NOT EXISTS (
        SELECT 1 FROM events e
         WHERE e.stream_id  = 'artifact-' || a.id::text
           AND e.event_type = 'ArtifactExpired'
           AND jsonb_typeof(e.event_data->'data'->'reason') = 'object'
           AND NOT (e.event_data->'data'->'reason' ? 'KeepLastN')
    )
"#;

/// SQL for `user_deleted`: an `ArtifactDeleted` is on the artifact's
/// stream. Expects the artifacts row in scope as `a`; binds nothing.
/// Shared by the same two readers, for the same reason as the
/// predicate above.
const ARTIFACT_USER_DELETED_SQL: &str = r#"
    EXISTS (
        SELECT 1 FROM events e
         WHERE e.stream_id  = 'artifact-' || a.id::text
           AND e.event_type = 'ArtifactDeleted'
    )
"#;

/// The artifact row as read under the `FOR UPDATE` lock that opens the
/// worklist preparation: the authoritative `checksum_sha256` for the
/// idempotent-retry path, plus the four facts the two protection rules
/// are computed from.
#[derive(Debug, FromRow)]
struct LockedArtifactRow {
    checksum_sha256: String,
    quarantine_status: Option<String>,
    tag_targeted: bool,
    expired_only_by_keep_last_n: bool,
    user_deleted: bool,
}

/// One `(target_content_hash, kind)` row removed by the step-2
/// `DELETE … RETURNING`, or recovered from the authoritative columns
/// on an idempotent retry.
#[derive(Debug, FromRow)]
struct DeletedRefRow {
    target_content_hash: String,
}

#[derive(Debug, Clone, FromRow)]
struct WorklistRow {
    content_hash: String,
    refs_remaining: i64,
    completed_at: Option<DateTime<Utc>>,
}

/// Map the persisted `artifacts.quarantine_status` text to the domain
/// [`QuarantineStatus`]. The GC-protected set is filtered in SQL, so
/// any value the use case re-checks must round-trip; an unknown value
/// is a data-integrity error rather than a silent mis-classification of
/// a destructive decision.
///
/// Delegates to the crate's one
/// [`quarantine_status_from_sql`](crate::quarantine_status_sql::quarantine_status_from_sql)
/// codec, so this mapper is not a second author of the column's
/// vocabulary. It used to collapse the legacy scan-state spellings
/// (`unscanned` / `clean` / `flagged`) to [`QuarantineStatus::None`] on
/// its own — on this path, "not GC-protected" — which is a destructive
/// decision taken from a value the domain cannot classify.
///
/// The error surfaces through `list_pending`, so an unclassifiable row
/// fails that whole page rather than only its own artifact. That is the
/// fail-closed direction for a purge (nothing is deleted), and the
/// condition is not one a migrated database can be in:
/// `030_artifacts_quarantine_status_legacy_backfill.sql` replaces the
/// legacy spellings with the held state (`'quarantined'` plus a window
/// anchor), which this mapper classifies as GC-protected.
pub(crate) fn map_status(raw: Option<&str>) -> DomainResult<QuarantineStatus> {
    crate::quarantine_status_sql::quarantine_status_from_sql(raw, || {
        "purge_gc: pending-purge artifact".to_string()
    })
}

/// Parse a DB hash column into a [`ContentHash`], trimming the
/// blank-padding `character(64)` columns carry. A corrupt value is a
/// data-integrity error (mirrors `refcount_reconcile::parse_hash`).
fn parse_hash(raw: &str, ctx: &str) -> DomainResult<ContentHash> {
    ContentHash::from_str(raw.trim())
        .map_err(|_| DomainError::Invariant(format!("purge_gc: corrupt hash {raw:?} ({ctx})")))
}

/// A held [`blob_lock`](crate::blob_lock), carried as the open
/// transaction that owns it.
///
/// The lock has to outlive the transaction that *decided* — the
/// worklist preparation commits long before the sweep reaches the
/// bytes, and on a retry it may have committed a day earlier. So this
/// guard is a second, deliberately short transaction that does nothing
/// but hold the lock and the count it read under it, kept open across
/// `StoragePort::delete` and closed immediately after.
///
/// It is read-only: `pg_try_advisory_xact_lock` and one `count(*)`.
/// Nothing is pending in it, so the only cost of holding it open is one
/// pooled connection for the duration of one blob delete. Dropping it
/// without [`release`](BlobReclaimGuard::release) queues a rollback on
/// the connection — which also ends the lock — so a lost guard cannot
/// strand the lock the way a session-scoped `pg_advisory_lock` would.
struct PgBlobReclaimGuard {
    tx: Transaction<'static, Postgres>,
}

impl BlobReclaimGuard for PgBlobReclaimGuard {
    fn release(self: Box<Self>) -> hort_domain::ports::BoxFuture<'static, DomainResult<()>> {
        Box::pin(async move {
            // Commit rather than roll back: the transaction wrote
            // nothing, so the two are equivalent in effect, and a
            // commit is the statement that says "this lease ended
            // normally" to anyone reading the session's log.
            self.tx
                .commit()
                .await
                .map_err(|e| map_sqlx_error(&e, "purge_gc", "release_blob_lock"))
        })
    }
}

impl PgPurgeGcPort {
    /// Cross-`kind` remaining `content_references` count for one hash,
    /// run inside the open transaction so it observes the step-2
    /// `DELETE`. Counts **every** kind (incl. `oci_subject` and each
    /// `oci_index_member` edge from a live image index).
    async fn remaining_refs(
        tx: &mut Transaction<'_, Postgres>,
        hash: &ContentHash,
    ) -> DomainResult<u32> {
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM content_references WHERE target_content_hash = $1",
        )
        .bind(hash.as_ref())
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| map_sqlx_error(&e, "purge_gc", "count_refs"))?;
        Ok(u32::try_from(count.max(0)).unwrap_or(u32::MAX))
    }

    /// How many non-deleted **GC-protected** artifacts claim `hash` —
    /// run inside the blob-lock transaction, on the path that would
    /// otherwise delete.
    ///
    /// `remaining_refs` above counts `content_references` rows, and
    /// protected evidence has none to count: `refcount_reconcile`
    /// deliberately mints no edge for a `quarantined` / `rejected` /
    /// `scan_indeterminate` artifact, so that a repaired refcount
    /// cannot make a quarantined blob look GC-protected for the wrong
    /// reason. The two protections that do exist — `list_pending_purge`
    /// never offering such an artifact, and
    /// `retention_candidate_reader` never expiring one — protect the
    /// *artifact*. Nothing in them protects the *bytes*, and CAS shares
    /// bytes across artifacts: a released sibling with the same hash
    /// reaches this delete with the protected artifact never having
    /// been a candidate. This count is what keeps the bytes.
    ///
    /// **Two hashes per artifact, not one.** A protected artifact
    /// claims its primary content (`artifacts.checksum_sha256`) *and*
    /// its metadata blob (`artifact_metadata.metadata_blob`, a
    /// different table). Asking only the first leaves half the hole
    /// open. Both columns are `character(64)` and are compared trimmed,
    /// matching `parse_hash` here and `refcount_reconcile`'s
    /// `trim(am.metadata_blob)`.
    ///
    /// The protected status list is bound from
    /// [`crate::gc_protected_quarantine_status_names`] — the same
    /// function the other three filters bind — because a second literal
    /// list is exactly the drift that opened this hole.
    ///
    /// `UNION` rather than `UNION ALL`: an artifact whose primary
    /// content and metadata blob are the same hash is one claimant, not
    /// two, which is what makes the returned number a count of
    /// artifacts holding the bytes.
    async fn protected_claimants(
        tx: &mut Transaction<'_, Postgres>,
        hash: &ContentHash,
    ) -> DomainResult<u32> {
        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT count(*) FROM (
                SELECT a.id
                  FROM artifacts a
                 WHERE a.deleted_at IS NULL
                   AND a.quarantine_status = ANY($1::text[])
                   AND trim(a.checksum_sha256) = $2
                UNION
                SELECT a.id
                  FROM artifacts a
                  JOIN artifact_metadata am
                    ON am.artifact_id = a.id
                 WHERE a.deleted_at IS NULL
                   AND a.quarantine_status = ANY($1::text[])
                   AND am.metadata_blob IS NOT NULL
                   AND trim(am.metadata_blob) = $2
            ) claimants
            "#,
        )
        .bind(crate::gc_protected_quarantine_status_names())
        .bind(hash.as_ref())
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| map_sqlx_error(&e, "purge_gc", "count_protected_claimants"))?;
        Ok(u32::try_from(count.max(0)).unwrap_or(u32::MAX))
    }

    /// Correct a worklist row's `refs_remaining` to the claim count
    /// observed under the blob lock, so the terminal `ArtifactPurged`
    /// states what actually held and a later retry reads the same
    /// thing.
    ///
    /// Not optional bookkeeping: `validate_terminal_batch` refuses a
    /// terminal batch whose events disagree with the worklist, so a
    /// keep that skipped this would make the artifact's purge
    /// permanently unfinishable. A missing row is loud for the same
    /// reason — there is nowhere for the corrected count to land.
    async fn refresh_worklist_refs(
        tx: &mut Transaction<'_, Postgres>,
        artifact_id: Uuid,
        hash: &ContentHash,
        claims: u32,
    ) -> DomainResult<()> {
        let updated = sqlx::query(
            "UPDATE artifact_purge_worklist SET refs_remaining = $3 \
             WHERE artifact_id = $1 AND content_hash = $2",
        )
        .bind(artifact_id)
        .bind(hash.as_ref())
        .bind(i64::from(claims))
        .execute(&mut **tx)
        .await
        .map_err(|e| map_sqlx_error(&e, "purge_gc", "refresh_worklist_refs"))?;
        if updated.rows_affected() != 1 {
            return Err(DomainError::Invariant(format!(
                "purge_gc: no worklist row for artifact {artifact_id} hash {hash}"
            )));
        }
        Ok(())
    }

    async fn load_worklist(
        tx: &mut Transaction<'_, Postgres>,
        artifact_id: Uuid,
    ) -> DomainResult<Vec<WorklistRow>> {
        sqlx::query_as(
            r#"
            SELECT content_hash, refs_remaining, completed_at
              FROM artifact_purge_worklist
             WHERE artifact_id = $1
             ORDER BY content_hash
            "#,
        )
        .bind(artifact_id)
        .fetch_all(&mut **tx)
        .await
        .map_err(|e| map_sqlx_error(&e, "purge_gc", "load_worklist"))
    }

    /// Take the artifact out of service inside the preparation
    /// transaction — the retirement half of what used to be the
    /// terminal transition's single write.
    ///
    /// `COALESCE` keeps the **earlier** timestamp: a caller-facing
    /// delete already recorded the moment the artifact left service and
    /// the purge time must not overwrite that audit fact. That also
    /// makes the write idempotent, which is what lets every `Prepared`
    /// branch call it unconditionally.
    ///
    /// `updated_at` moves only on the call that actually retires. Every
    /// `Prepared` branch calls this, including the retry branch of an
    /// artifact that spends several sweeps deferred, and a row whose
    /// `deleted_at` this call left alone did not change — advancing its
    /// modification time on every sweep would say otherwise. The `CASE`
    /// reads the pre-update row, so it tracks the `COALESCE` beside it.
    ///
    /// `Ok(false)` means the row is no longer there. The worklist is
    /// `ON DELETE CASCADE`-tied to it, so a vanished artifact has
    /// nothing left to release and the caller answers
    /// `PurgePreparation::NoArtifact`. That is the only thing
    /// `rows_affected` is asked, which is why no predicate beyond the
    /// id belongs in the `WHERE`.
    async fn retire_row(
        tx: &mut Transaction<'_, Postgres>,
        artifact_id: Uuid,
        retired_at: DateTime<Utc>,
    ) -> DomainResult<bool> {
        let updated = sqlx::query(
            "UPDATE artifacts \
                SET deleted_at = COALESCE(deleted_at, $2), \
                    updated_at = CASE WHEN deleted_at IS NULL THEN $2 ELSE updated_at END \
              WHERE id = $1",
        )
        .bind(artifact_id)
        .bind(retired_at)
        .execute(&mut **tx)
        .await
        .map_err(|e| map_sqlx_error(&e, "purge_gc", "retire_artifact_on_prepare"))?;
        Ok(updated.rows_affected() == 1)
    }

    fn map_worklist(rows: Vec<WorklistRow>) -> DomainResult<Vec<PurgedRef>> {
        rows.into_iter()
            .map(|row| {
                Ok(PurgedRef {
                    content_hash: parse_hash(&row.content_hash, "artifact_purge_worklist")?,
                    refs_remaining: u32::try_from(row.refs_remaining).map_err(|_| {
                        DomainError::Invariant(format!(
                            "purge_gc: invalid refs_remaining {} in worklist",
                            row.refs_remaining
                        ))
                    })?,
                    completed: row.completed_at.is_some(),
                })
            })
            .collect()
    }

    fn validate_terminal_batch(
        artifact_id: Uuid,
        retired_at: DateTime<Utc>,
        worklist: &[WorklistRow],
        batch: &AppendEvents,
    ) -> DomainResult<()> {
        if batch.stream_id != StreamId::artifact(artifact_id) {
            return Err(DomainError::Invariant(
                "purge_gc: terminal batch targets the wrong artifact stream".into(),
            ));
        }

        let expected: BTreeMap<_, _> = worklist
            .iter()
            .map(|row| (row.content_hash.trim().to_owned(), row.refs_remaining))
            .collect();
        let mut actual = BTreeMap::new();
        for event in &batch.events {
            let DomainEvent::ArtifactPurged(event) = &event.event else {
                return Err(DomainError::Invariant(
                    "purge_gc: terminal batch contains a non-ArtifactPurged event".into(),
                ));
            };
            if event.artifact_id != artifact_id || event.purged_at != retired_at {
                return Err(DomainError::Invariant(
                    "purge_gc: terminal event does not match its artifact transition".into(),
                ));
            }
            if actual
                .insert(
                    event.content_hash.as_ref().to_owned(),
                    i64::from(event.refs_remaining),
                )
                .is_some()
            {
                return Err(DomainError::Invariant(
                    "purge_gc: terminal batch contains a duplicate content hash".into(),
                ));
            }
        }
        if actual != expected {
            return Err(DomainError::Invariant(
                "purge_gc: terminal events do not exactly match the purge worklist".into(),
            ));
        }
        Ok(())
    }
}

impl PurgeGcPort for PgPurgeGcPort {
    fn list_pending_purge(
        &self,
        limit: u32,
        after_artifact_id: Option<Uuid>,
    ) -> BoxFuture<'_, DomainResult<Vec<PendingPurge>>> {
        Box::pin(async move {
            // An artifact stream serializes as `artifact-<uuid>`
            // (`StreamId::Display`). The pending-purge set is every
            // artifact whose stream carries a byte-release work item —
            // an `ArtifactExpired` or an `ArtifactDeleted` — and no
            // `ArtifactPurged`. Protected quarantine states are
            // excluded here (GC-protected invariant) — the destructive
            // path is never even offered an evidence artifact; the use
            // case re-asserts the same filter defence-in-depth, and
            // `purge_artifact_refs` asks a third time under the
            // artifact lock, because what this query returns is a page
            // snapshot and the states it reads keep moving while the
            // sweep works through that page. A
            // soft-deleted row is deliberately NOT excluded: `deleted_at`
            // marks an artifact out of service, which is the condition
            // for collecting its bytes, not against it.
            //
            // Keyset-paged on `a.id` (the existing sort key) and capped
            // at `limit`: the first sweep after a deployment faces the
            // entire backlog, and a work set whose size is only known
            // once it is fully loaded is not a set this query may
            // return.
            let sql = format!(
                r#"
                SELECT a.id                AS artifact_id,
                       a.quarantine_status AS quarantine_status,
                       {tag_targeted}      AS tag_targeted,
                       {keep_last_n_only}  AS expired_only_by_keep_last_n,
                       {user_deleted}      AS user_deleted
                -- DELETED-INCLUSIVE: this IS the worklist that collects
                -- deleted rows. The `EXISTS` below is the whole
                -- membership rule — an ArtifactExpired or ArtifactDeleted
                -- with no ArtifactPurged yet — and a liveness predicate
                -- would drop exactly the ArtifactDeleted half of it, so a
                -- user-deleted artifact's bytes would never be reclaimed.
                -- The set is deliberately `deleted_at`-agnostic in the
                -- other direction too: an expiry decision carries no
                -- `deleted_at` until the purge itself writes one.
                  FROM artifacts a
                 WHERE EXISTS (
                         SELECT 1 FROM events e
                          WHERE e.stream_id  = 'artifact-' || a.id::text
                            AND e.event_type IN ('ArtifactExpired',
                                                 'ArtifactDeleted')
                       )
                   AND NOT EXISTS (
                         SELECT 1 FROM events e
                          WHERE e.stream_id  = 'artifact-' || a.id::text
                            AND e.event_type = 'ArtifactPurged'
                       )
                   AND (a.quarantine_status IS NULL
                        OR a.quarantine_status <> ALL($1::text[]))
                   AND ($2::uuid IS NULL OR a.id > $2::uuid)
                 ORDER BY a.id
                 LIMIT $3
                "#,
                tag_targeted = crate::ARTIFACT_IS_TAG_TARGETED_SQL,
                keep_last_n_only = ARTIFACT_EXPIRED_ONLY_BY_KEEP_LAST_N_SQL,
                user_deleted = ARTIFACT_USER_DELETED_SQL,
            );
            // Injection audit: every interpolated fragment is a crate
            // `const` (`ARTIFACT_IS_TAG_TARGETED_SQL`,
            // `ARTIFACT_EXPIRED_ONLY_BY_KEEP_LAST_N_SQL`,
            // `ARTIFACT_USER_DELETED_SQL`) — compile-time literals, not
            // runtime values. Every runtime value this statement uses is
            // bound ($1..$3). The assertion is sound as long as that stays
            // true: a fragment built from anything a caller supplies
            // must be bound instead, never formatted in.
            let rows: Vec<PendingRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
                .bind(crate::gc_protected_quarantine_status_names())
                .bind(after_artifact_id)
                .bind(i64::from(limit))
                .fetch_all(&self.pool)
                .await
                .map_err(|e| map_sqlx_error(&e, "purge_gc", "list_pending"))?;

            let mut out = Vec::with_capacity(rows.len());
            for row in rows {
                out.push(PendingPurge {
                    artifact_id: row.artifact_id,
                    quarantine_status: map_status(row.quarantine_status.as_deref())?,
                    tag_targeted: row.tag_targeted,
                    expired_only_by_keep_last_n: row.expired_only_by_keep_last_n,
                    user_deleted: row.user_deleted,
                });
            }
            Ok(out)
        })
    }

    fn purge_artifact_refs(
        &self,
        artifact_id: Uuid,
        retired_at: DateTime<Utc>,
    ) -> BoxFuture<'_, DomainResult<PurgePreparation>> {
        Box::pin(async move {
            let mut tx = self.pool.begin().await.map_err(|e| {
                DomainError::Invariant(format!("purge_gc purge_artifact_refs begin: {e}"))
            })?;

            let existing = Self::load_worklist(&mut tx, artifact_id).await?;
            if !existing.is_empty() {
                // A worklist means the edges are already gone, so this
                // artifact is on its way out of service whatever this
                // call does next — re-assert the retirement rather than
                // leaving it to the branch that happened to create the
                // worklist. `Prepared` then means the same thing on
                // every path: the row is retired, in this commit.
                // (`COALESCE` makes the re-assertion a no-op once it is
                // set; the branch earns its keep for a worklist
                // prepared by a build that retired at the end.)
                if !Self::retire_row(&mut tx, artifact_id, retired_at).await? {
                    tx.commit().await.map_err(|e| {
                        DomainError::Invariant(format!("purge_gc commit (no-artifact): {e}"))
                    })?;
                    return Ok(PurgePreparation::NoArtifact);
                }
                tx.commit().await.map_err(|e| {
                    DomainError::Invariant(format!("purge_gc worklist-read commit: {e}"))
                })?;
                return Self::map_worklist(existing).map(PurgePreparation::Prepared);
            }

            // Locking serializes first-time preparation. Once a
            // worklist exists, it is the authoritative target set and
            // no deleted edge needs to be reconstructed. The initial
            // worklist read happens before this artifact lock so a
            // normal retry cannot invert the final transition's
            // worklist -> events -> artifact lock order.
            //
            // The lock also carries the protection facts, and that is
            // the point of reading them here rather than trusting the
            // page row the caller holds: this statement runs in the
            // transaction that is about to delete the edges, and the
            // page row was taken before the sweep processed a single
            // item of its page.
            //
            // For `quarantine_status` the lock makes the read
            // conclusive — a scan writing that column takes the same
            // row lock, so this either waits for it and then observes
            // the committed value (`FOR UPDATE` re-fetches the latest
            // row version) or the write was already committed and is
            // read. The tag fact lives in `mutable_refs` and a ref
            // write takes no artifact lock, so what this cannot see is
            // a tag committing after it — which is what "after the
            // purge" means anywhere. What it does close is the page.
            let sql = format!(
                r#"
                SELECT a.checksum_sha256   AS checksum_sha256,
                       a.quarantine_status AS quarantine_status,
                       {tag_targeted}      AS tag_targeted,
                       {keep_last_n_only}  AS expired_only_by_keep_last_n,
                       {user_deleted}      AS user_deleted
                -- DELETED-INCLUSIVE: the row lock a purge takes before
                -- acting, on an artifact `list_pending_purge` just handed
                -- it — and that set admits soft-deleted rows on purpose.
                -- A liveness predicate here would report `NoArtifact` for
                -- work the sweep had just selected, so every user-deleted
                -- artifact would cycle through the worklist forever
                -- without being purged.
                  FROM artifacts a
                 WHERE a.id = $1
                   FOR UPDATE
                "#,
                tag_targeted = crate::ARTIFACT_IS_TAG_TARGETED_SQL,
                keep_last_n_only = ARTIFACT_EXPIRED_ONLY_BY_KEEP_LAST_N_SQL,
                user_deleted = ARTIFACT_USER_DELETED_SQL,
            );
            // Injection audit: same shape as `list_pending_purge`'s — the
            // three interpolated fragments are crate `const`s, so the
            // statement text is fixed at compile time, and the only
            // runtime value (`artifact_id`) is bound ($1).
            let locked: Option<LockedArtifactRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
                .bind(artifact_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| map_sqlx_error(&e, "purge_gc", "lock_artifact"))?;
            let Some(locked) = locked else {
                tx.commit().await.map_err(|e| {
                    DomainError::Invariant(format!("purge_gc commit (no-artifact): {e}"))
                })?;
                return Ok(PurgePreparation::NoArtifact);
            };
            let checksum_sha256 = locked.checksum_sha256;

            // Another first-time preparer may have committed while this
            // transaction waited for the artifact lock.
            //
            // Answered before the protection facts are consulted, and
            // in that order on purpose: a committed worklist means the
            // edges are already gone, so refusing now would strand an
            // artifact whose terminal event can never be appended and
            // whose purge therefore never finishes. From here the claim
            // check in `begin_blob_reclaim` is what protects the bytes,
            // and it asks about the hash rather than the artifact.
            let existing = Self::load_worklist(&mut tx, artifact_id).await?;
            if !existing.is_empty() {
                // Same re-assertion as the pre-lock branch, and here
                // the row lock is already held, so the write cannot
                // find the row missing.
                Self::retire_row(&mut tx, artifact_id, retired_at).await?;
                tx.commit().await.map_err(|e| {
                    DomainError::Invariant(format!("purge_gc worklist-read commit: {e}"))
                })?;
                return Self::map_worklist(existing).map(PurgePreparation::Prepared);
            }

            // The two protection rules, computed by the port's own
            // predicates from the facts just read under the lock — one
            // author for a rule the page reader also asks, so the two
            // readings cannot drift into two rules.
            //
            // An unclassifiable `quarantine_status` fails the whole
            // preparation here (`map_status` is fail-closed) rather
            // than reading as "not protected": the next statement
            // deletes.
            let fresh = PendingPurge {
                artifact_id,
                quarantine_status: map_status(locked.quarantine_status.as_deref())?,
                tag_targeted: locked.tag_targeted,
                expired_only_by_keep_last_n: locked.expired_only_by_keep_last_n,
                user_deleted: locked.user_deleted,
            };
            let refusal = if fresh.is_gc_protected() {
                Some(PurgePreparation::Protected {
                    status: fresh.quarantine_status,
                })
            } else if fresh.is_tag_exempt() {
                Some(PurgePreparation::TagExempt)
            } else {
                None
            };
            if let Some(outcome) = refusal {
                // Nothing was written, so commit and rollback are the
                // same in effect; commit is the one that says the
                // transaction ended normally. Either way the lock ends
                // here and the work item is left pending.
                tx.commit().await.map_err(|e| {
                    DomainError::Invariant(format!("purge_gc commit (protection re-read): {e}"))
                })?;
                return Ok(outcome);
            }

            // Retire the artifact BEFORE the first destructive
            // statement, in the transaction that performs it. This is
            // the whole ordering: `artifacts.deleted_at` is what takes
            // the row out of service (`Artifact::is_downloadable` is
            // false once it is set, and the read paths filter
            // `deleted_at IS NULL`), so it has to be durable before any
            // byte can go missing underneath it. Written at the terminal
            // transition instead, it arrived only after every hash of
            // every preceding artifact had been deleted — and inside
            // that window a reader resolved the row, passed the
            // downloadable gate and then hit a CAS read with no blob
            // behind it, which surfaces as an opaque 500 rather than the
            // 404 the retirement produces.
            //
            // Statement order inside one transaction changes nothing a
            // reader can see — the commit does that — but it is read as
            // the contract, so the write that retires stands ahead of
            // the write that destroys.
            //
            // Past the protection re-read above on purpose: a refusal
            // must leave the artifact in service, and only a `Prepared`
            // outcome retires it. The row lock is held, so this cannot
            // find the row gone.
            Self::retire_row(&mut tx, artifact_id, retired_at).await?;

            // Remove every source-edge kind. A purge retains its
            // artifact row for audit, so no FK cascade can perform
            // this sweep later.
            let deleted: Vec<DeletedRefRow> = sqlx::query_as(
                r#"
                DELETE FROM content_references
                 WHERE source_artifact_id = $1
             RETURNING target_content_hash
                "#,
            )
            .bind(artifact_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| map_sqlx_error(&e, "purge_gc", "delete_refs"))?;

            // Distinct targets across every reference kind are captured
            // before this transaction commits. The fallback supports a
            // projection that was already missing its single-target
            // rows before durable worklists existed; retries of this
            // implementation always take the worklist branch above.
            let mut hashes: BTreeMap<String, ContentHash> = BTreeMap::new();
            for row in &deleted {
                let h = parse_hash(
                    &row.target_content_hash,
                    "content_references.target_content_hash",
                )?;
                hashes.insert(h.as_ref().to_owned(), h);
            }
            if hashes.is_empty() {
                let primary = parse_hash(&checksum_sha256, "artifacts.checksum_sha256")?;
                hashes.insert(primary.as_ref().to_owned(), primary);

                let meta_blob: Option<Option<String>> = sqlx::query_scalar(
                    "SELECT metadata_blob FROM artifact_metadata WHERE artifact_id = $1",
                )
                .bind(artifact_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| map_sqlx_error(&e, "purge_gc", "recover_metadata_blob"))?;
                if let Some(Some(raw)) = meta_blob {
                    let trimmed = raw.trim();
                    if !trimmed.is_empty() {
                        let mh = parse_hash(trimmed, "artifact_metadata.metadata_blob")?;
                        hashes.insert(mh.as_ref().to_owned(), mh);
                    }
                }
            }

            // Persist the post-delete decision for every hash before
            // the deleted edges become invisible to later attempts.
            for hash in hashes.into_values() {
                let refs_remaining = Self::remaining_refs(&mut tx, &hash).await?;
                sqlx::query(
                    r#"
                    INSERT INTO artifact_purge_worklist (
                        artifact_id, content_hash, refs_remaining
                    ) VALUES ($1, $2, $3)
                    "#,
                )
                .bind(artifact_id)
                .bind(hash.as_ref())
                .bind(i64::from(refs_remaining))
                .execute(&mut *tx)
                .await
                .map_err(|e| map_sqlx_error(&e, "purge_gc", "insert_worklist"))?;
            }

            let worklist = Self::load_worklist(&mut tx, artifact_id).await?;
            tx.commit().await.map_err(|e| {
                DomainError::Invariant(format!("purge_gc purge_artifact_refs commit: {e}"))
            })?;
            Self::map_worklist(worklist).map(PurgePreparation::Prepared)
        })
    }

    fn begin_blob_reclaim(
        &self,
        artifact_id: Uuid,
        content_hash: &ContentHash,
    ) -> BoxFuture<'_, DomainResult<BlobReclaim>> {
        let hash = content_hash.clone();
        Box::pin(async move {
            let mut tx = self.pool.begin().await.map_err(|e| {
                DomainError::Invariant(format!("purge_gc begin_blob_reclaim begin: {e}"))
            })?;

            // Try, never wait. The lock's other holder is a
            // reference write serving a request; a destructive sweep
            // that queued behind it would be trading a user-visible
            // stall for housekeeping it is explicitly allowed to defer.
            if !crate::blob_lock::try_lock_blob_in_tx(&mut tx, &hash).await? {
                tx.rollback().await.map_err(|e| {
                    DomainError::Invariant(format!("purge_gc blob-lock contended rollback: {e}"))
                })?;
                return Ok(BlobReclaim::Contended);
            }

            // The authoritative count, read under the lock. The
            // worklist's `refs_remaining` was computed in a transaction
            // that has already committed — potentially in an earlier
            // sweep — so it is a snapshot, and a snapshot is not
            // permission to delete.
            let refs_now = Self::remaining_refs(&mut tx, &hash).await?;
            if refs_now > 0 {
                // Something re-referenced these bytes. The blob is
                // alive; correct the worklist so the `ArtifactPurged`
                // the caller emits carries the count that actually
                // held rather than the stale zero, then let go.
                Self::refresh_worklist_refs(&mut tx, artifact_id, &hash, refs_now).await?;
                tx.commit().await.map_err(|e| {
                    DomainError::Invariant(format!("purge_gc blob-lock refresh commit: {e}"))
                })?;
                return Ok(BlobReclaim::Referenced { refs_now });
            }

            // The refcount is genuinely zero — and a `content_references`
            // row is not the only claim on a blob. Ask the second
            // question only here, on the path that would otherwise
            // delete: a non-zero count above already keeps the bytes,
            // so there would be nothing for the answer to decide.
            let claimants = Self::protected_claimants(&mut tx, &hash).await?;
            if claimants > 0 {
                Self::refresh_worklist_refs(&mut tx, artifact_id, &hash, claimants).await?;
                tx.commit().await.map_err(|e| {
                    DomainError::Invariant(format!("purge_gc protected-claim commit: {e}"))
                })?;
                return Ok(BlobReclaim::ProtectedClaim { claimants });
            }

            Ok(BlobReclaim::Granted(Box::new(PgBlobReclaimGuard { tx })))
        })
    }

    fn mark_purge_ref_complete(
        &self,
        artifact_id: Uuid,
        content_hash: &ContentHash,
        completed_at: DateTime<Utc>,
    ) -> BoxFuture<'_, DomainResult<()>> {
        let content_hash = content_hash.clone();
        Box::pin(async move {
            let result = sqlx::query(
                "UPDATE artifact_purge_worklist \
                 SET completed_at = COALESCE(completed_at, $3) \
                 WHERE artifact_id = $1 AND content_hash = $2",
            )
            .bind(artifact_id)
            .bind(content_hash.as_ref())
            .bind(completed_at)
            .execute(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "purge_gc", "complete_worklist_ref"))?;
            if result.rows_affected() != 1 {
                return Err(DomainError::Invariant(format!(
                    "purge_gc: no worklist row for artifact {artifact_id} hash {content_hash}"
                )));
            }
            Ok(())
        })
    }

    fn complete_artifact_purge(
        &self,
        artifact_id: Uuid,
        retired_at: DateTime<Utc>,
        events: AppendEvents,
    ) -> BoxFuture<'_, DomainResult<()>> {
        Box::pin(async move {
            let mut uow = self.event_store.begin_unit_of_work().await?;
            let worklist: Vec<WorklistRow> = sqlx::query_as(
                r#"
                SELECT content_hash, refs_remaining, completed_at
                  FROM artifact_purge_worklist
                 WHERE artifact_id = $1
                 ORDER BY content_hash
                   FOR UPDATE
                "#,
            )
            .bind(artifact_id)
            .fetch_all(uow.conn())
            .await
            .map_err(|e| map_sqlx_error(&e, "purge_gc", "lock_worklist"))?;

            if worklist.is_empty() {
                return Err(DomainError::Invariant(format!(
                    "purge_gc: artifact {artifact_id} has no purge worklist"
                )));
            }
            if worklist.iter().any(|row| row.completed_at.is_none()) {
                return Err(DomainError::Invariant(format!(
                    "purge_gc: artifact {artifact_id} still has incomplete storage work"
                )));
            }
            Self::validate_terminal_batch(artifact_id, retired_at, &worklist, &events)?;

            self.event_store.append_in_tx(&mut uow, events).await?;

            #[cfg(test)]
            if self.interrupt_after_append.swap(false, Ordering::SeqCst) {
                return Err(DomainError::Invariant(
                    "purge_gc: injected interruption after terminal append".into(),
                ));
            }

            // Idempotent in the state, not in the writer: the row must
            // end up retired, whoever retired it. By the time this runs
            // `purge_artifact_refs` has already retired it, so on the
            // normal path `COALESCE` makes this a no-op on `deleted_at`
            // — but the state, not the writer, is what the idempotency
            // is about, and two other writers reach it: a user-facing
            // delete that landed between the expiry decision and this
            // sweep (the pending-purge set has no `deleted_at`
            // predicate), and a worklist prepared by a build that
            // retired only here. An unconditional `deleted_at IS NULL`
            // guard would fail this transition on every retry, leaving
            // an artifact whose blobs are gone, whose row lives, and
            // whose stream carries no terminal event. `COALESCE` keeps
            // the *earlier* timestamp: the moment the artifact left
            // service is the audit fact, and overwriting it with the
            // purge time would erase it. Matching on `id` alone still
            // affects zero rows — and so still yields `NotFound` — when
            // the row is genuinely absent, which is this statement's
            // other job.
            let updated = sqlx::query(
                "UPDATE artifacts SET deleted_at = COALESCE(deleted_at, $2), updated_at = $2 \
                 WHERE id = $1",
            )
            .bind(artifact_id)
            .bind(retired_at)
            .execute(uow.conn())
            .await
            .map_err(|e| map_sqlx_error(&e, "purge_gc", "retire_artifact"))?;
            if updated.rows_affected() != 1 {
                return Err(DomainError::NotFound {
                    entity: "Artifact",
                    id: artifact_id.to_string(),
                });
            }

            sqlx::query("DELETE FROM artifact_purge_worklist WHERE artifact_id = $1")
                .bind(artifact_id)
                .execute(uow.conn())
                .await
                .map_err(|e| map_sqlx_error(&e, "purge_gc", "clear_worklist"))?;

            uow.commit().await?;
            Ok(())
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Mutex;

    use hort_app::use_cases::purge_use_case::{PurgeUseCase, RefcountReconcileGate};
    use hort_domain::ports::artifact_repository::ArtifactRepository;
    use hort_domain::ports::refcount_reconcile::RefcountReconcilePort;
    use hort_domain::ports::storage::StoragePort;
    use hort_domain::types::ByteRange;
    use serial_test::serial;
    use tokio::io::AsyncReadExt;

    const HASH_A: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const HASH_B: &str = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
    const HASH_C: &str = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae";

    struct ConvergedGate;

    impl RefcountReconcileGate for ConvergedGate {
        fn is_converged(&self) -> bool {
            true
        }
    }

    struct FailDeleteOnceStorage {
        inner: hort_adapters_storage::FilesystemStorage,
        fail_once: Mutex<HashSet<ContentHash>>,
    }

    impl FailDeleteOnceStorage {
        fn new(inner: hort_adapters_storage::FilesystemStorage, hash: ContentHash) -> Self {
            Self {
                inner,
                fail_once: Mutex::new(HashSet::from([hash])),
            }
        }
    }

    impl StoragePort for FailDeleteOnceStorage {
        fn put(
            &self,
            stream: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        ) -> BoxFuture<'_, DomainResult<hort_domain::ports::storage::PutResult>> {
            self.inner.put(stream)
        }

        fn get(
            &self,
            hash: &ContentHash,
        ) -> BoxFuture<'_, DomainResult<Box<dyn tokio::io::AsyncRead + Send + Unpin>>> {
            self.inner.get(hash)
        }

        fn get_range(
            &self,
            hash: &ContentHash,
            range: ByteRange,
        ) -> BoxFuture<'_, DomainResult<Box<dyn tokio::io::AsyncRead + Send + Unpin>>> {
            self.inner.get_range(hash, range)
        }

        fn exists(&self, hash: &ContentHash) -> BoxFuture<'_, DomainResult<bool>> {
            self.inner.exists(hash)
        }

        fn delete(&self, hash: &ContentHash) -> BoxFuture<'_, DomainResult<()>> {
            let fail = self.fail_once.lock().unwrap().remove(hash);
            if fail {
                let hash = hash.to_string();
                Box::pin(async move {
                    Err(DomainError::Invariant(format!(
                        "injected storage delete failure for {hash}"
                    )))
                })
            } else {
                self.inner.delete(hash)
            }
        }

        fn size_of(&self, hash: &ContentHash) -> BoxFuture<'_, DomainResult<u64>> {
            self.inner.size_of(hash)
        }
    }

    // -- pure unit -----------------------------------------------------

    #[test]
    fn adapter_implements_port() {
        fn _assert_port<T: PurgeGcPort>() {}
        _assert_port::<PgPurgeGcPort>();
    }

    #[test]
    fn map_status_maps_every_stored_value() {
        assert_eq!(map_status(None).unwrap(), QuarantineStatus::None);
        assert_eq!(
            map_status(Some("released")).unwrap(),
            QuarantineStatus::Released
        );
        assert_eq!(
            map_status(Some("quarantined")).unwrap(),
            QuarantineStatus::Quarantined
        );
        assert_eq!(
            map_status(Some("rejected")).unwrap(),
            QuarantineStatus::Rejected
        );
        assert_eq!(
            map_status(Some("scan_indeterminate")).unwrap(),
            QuarantineStatus::ScanIndeterminate
        );
    }

    /// The legacy scan-state spellings used to collapse to
    /// `QuarantineStatus::None` here, which on this path reads as "this
    /// blob is not GC-protected" — a destructive decision taken from a
    /// value the domain cannot classify. They now stop the purge for
    /// that artifact instead.
    #[test]
    fn map_status_no_longer_collapses_the_legacy_scan_states() {
        for raw in ["unscanned", "clean", "flagged"] {
            let err = map_status(Some(raw)).unwrap_err();
            assert!(
                matches!(err, DomainError::Invariant(_)),
                "{raw} must not classify"
            );
            assert!(
                err.to_string().contains(raw),
                "the error must name the value; got {err}"
            );
        }
    }

    #[test]
    fn map_status_rejects_unknown() {
        let err = map_status(Some("bogus")).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
        assert!(err.to_string().contains("unclassifiable quarantine_status"));
    }

    #[test]
    fn parse_hash_trims_padding_and_parses() {
        let padded = format!("{HASH_A}   ");
        assert_eq!(parse_hash(&padded, "test").unwrap().as_ref(), HASH_A);
    }

    #[test]
    fn parse_hash_rejects_corrupt() {
        let err = parse_hash("not-a-hash", "test ctx").unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
        assert!(err.to_string().contains("corrupt hash"));
        assert!(err.to_string().contains("test ctx"));
    }

    // -- DB-backed integration tests -----------------------------------
    //
    // Skipped (silent return) when `DATABASE_URL` is unset — mirrors
    // `refcount_reconcile.rs` / `pg_content_reference_repo.rs`. Each
    // test seeds throwaway rows under a fresh repo and cleans up with
    // the repo-row `ON DELETE CASCADE`. `#[serial(hort_pg_db)]` because
    // the hort-adapters-postgres `--lib` DB suite shares one database
    // with no per-test isolation (commit ed79360a).

    use std::env;

    async fn maybe_pool() -> Option<PgPool> {
        let url = env::var("DATABASE_URL").ok()?;
        let pool = crate::test_support::isolated_db_from(&url).await?;
        crate::test_support::migrate_or_panic(&pool).await;
        Some(pool)
    }

    async fn adapter(pool: &PgPool) -> PgPurgeGcPort {
        let event_store = Arc::new(PgEventStore::new(pool.clone()).await.unwrap());
        PgPurgeGcPort::new(pool.clone(), event_store)
    }

    /// Unwrap the prepared worklist, failing loudly on any of the
    /// three refusals. A test that is about the worklist wants to know
    /// that it got one — a refusal silently read as "no rows" is the
    /// shape this whole outcome type exists to prevent.
    fn prepared(outcome: PurgePreparation) -> Vec<PurgedRef> {
        match outcome {
            PurgePreparation::Prepared(refs) => refs,
            other => panic!("expected a prepared worklist, got {other:?}"),
        }
    }

    fn terminal_batch(
        artifact_id: Uuid,
        refs: &[PurgedRef],
        retired_at: DateTime<Utc>,
    ) -> AppendEvents {
        AppendEvents {
            stream_id: StreamId::artifact(artifact_id),
            expected_version: hort_domain::ports::event_store::ExpectedVersion::Any,
            events: refs
                .iter()
                .map(|purged_ref| {
                    hort_domain::ports::event_store::EventToAppend::new(
                        DomainEvent::ArtifactPurged(hort_domain::events::ArtifactPurged {
                            artifact_id,
                            content_hash: purged_ref.content_hash.clone(),
                            refs_remaining: purged_ref.refs_remaining,
                            purged_at: retired_at,
                        }),
                    )
                })
                .collect(),
            correlation_id: Uuid::new_v4(),
            causation_id: None,
            actor: hort_domain::events::retention_scheduler_actor(),
        }
    }

    #[test]
    fn worklist_mapping_and_terminal_batch_validation_are_fail_closed() {
        let artifact_id = Uuid::new_v4();
        let retired_at = DateTime::from_timestamp(1_000, 0).unwrap();
        let rows = vec![WorklistRow {
            content_hash: HASH_A.into(),
            refs_remaining: 0,
            completed_at: Some(retired_at),
        }];
        let refs = PgPurgeGcPort::map_worklist(rows.clone()).unwrap();
        assert!(refs[0].completed);
        let valid = terminal_batch(artifact_id, &refs, retired_at);
        PgPurgeGcPort::validate_terminal_batch(artifact_id, retired_at, &rows, &valid).unwrap();

        let wrong_stream = terminal_batch(Uuid::new_v4(), &refs, retired_at);
        assert!(PgPurgeGcPort::validate_terminal_batch(
            artifact_id,
            retired_at,
            &rows,
            &wrong_stream
        )
        .is_err());

        let wrong_time = terminal_batch(
            artifact_id,
            &refs,
            retired_at + chrono::Duration::seconds(1),
        );
        assert!(PgPurgeGcPort::validate_terminal_batch(
            artifact_id,
            retired_at,
            &rows,
            &wrong_time
        )
        .is_err());

        let duplicate_refs = vec![refs[0].clone(), refs[0].clone()];
        let duplicates = terminal_batch(artifact_id, &duplicate_refs, retired_at);
        assert!(PgPurgeGcPort::validate_terminal_batch(
            artifact_id,
            retired_at,
            &rows,
            &duplicates
        )
        .is_err());

        let missing = terminal_batch(artifact_id, &[], retired_at);
        assert!(
            PgPurgeGcPort::validate_terminal_batch(artifact_id, retired_at, &rows, &missing)
                .is_err()
        );

        let invalid_count = vec![WorklistRow {
            content_hash: HASH_A.into(),
            refs_remaining: -1,
            completed_at: None,
        }];
        assert!(PgPurgeGcPort::map_worklist(invalid_count).is_err());
    }

    async fn seed_repo(pool: &PgPool) -> Uuid {
        let id = Uuid::new_v4();
        let key = format!("it-purge-gc-{}", id.simple());
        sqlx::query(
            r#"INSERT INTO repositories (
                   id, key, name, format, repo_type, storage_backend, storage_path,
                   replication_priority
               ) VALUES (
                   $1, $2, $3,
                   'generic'::repository_format,
                   'hosted'::repository_type,
                   'filesystem', $4,
                   'local_only'::replication_priority
               )"#,
        )
        .bind(id)
        .bind(&key)
        .bind(&key)
        .bind(format!("/tmp/{key}"))
        .execute(pool)
        .await
        .expect("seed repo");
        id
    }

    async fn seed_artifact(
        pool: &PgPool,
        repo: Uuid,
        name: &str,
        checksum: &str,
        quarantine_status: Option<&str>,
    ) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO artifacts (
                   id, repository_id, name, name_as_published, version, path,
                   size_bytes, checksum_sha256, content_type, storage_key,
                   quarantine_status
               ) VALUES (
                   $1, $2, $3, $3, '1.0.0', $4,
                   0, $5, 'application/octet-stream', $4, $6
               )"#,
        )
        .bind(id)
        .bind(repo)
        .bind(name)
        .bind(format!("artifacts/{name}-{}", id.simple()))
        .bind(checksum)
        .bind(quarantine_status)
        .execute(pool)
        .await
        .expect("seed artifact");
        id
    }

    async fn seed_metadata_blob(pool: &PgPool, artifact: Uuid, blob_hash: &str) {
        sqlx::query(
            r#"INSERT INTO artifact_metadata (artifact_id, format, metadata_blob)
               VALUES ($1, 'generic', $2)"#,
        )
        .bind(artifact)
        .bind(blob_hash)
        .execute(pool)
        .await
        .expect("seed metadata blob");
    }

    async fn insert_cr(pool: &PgPool, repo: Uuid, source: Uuid, kind: &str, target: &str) {
        sqlx::query(
            r#"INSERT INTO content_references (
                   source_artifact_id, target_content_hash, kind, metadata,
                   repository_id, recorded_at
               ) VALUES ($1, $2, $3, '{}'::jsonb, $4, now())"#,
        )
        .bind(source)
        .bind(target)
        .bind(kind)
        .bind(repo)
        .execute(pool)
        .await
        .expect("seed content_references row");
    }

    /// Append a minimal artifact-stream event. `prev`/`event_hash` are
    /// 32-byte fillers — these tests exercise the GC SQL, not the
    /// chain verifier, so any 32-byte value satisfies the width
    /// CHECK. `stream_position` is supplied by the caller.
    async fn append_event(pool: &PgPool, artifact: Uuid, event_type: &str, stream_position: i64) {
        sqlx::query(
            r#"INSERT INTO events (
                   stream_id, stream_category, stream_position, event_type,
                   event_data, correlation_id, actor_type,
                   prev_event_hash, event_hash
               ) VALUES (
                   'artifact-' || $1::text, 'artifact', $2, $3,
                   '{}'::jsonb, gen_random_uuid(), 'system',
                   '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea,
                   '\x1111111111111111111111111111111111111111111111111111111111111111'::bytea
               )"#,
        )
        .bind(artifact)
        .bind(stream_position)
        .bind(event_type)
        .execute(pool)
        .await
        .expect("append event");
    }

    /// Append an artifact-stream event carrying a real payload —
    /// `{"type": …, "data": {"reason": <reason>}}`, the shape
    /// `serialize_event_data` writes for an externally-tagged
    /// `ExpirationReason`.
    async fn append_expired_with_reason(
        pool: &PgPool,
        artifact: Uuid,
        stream_position: i64,
        reason: serde_json::Value,
    ) {
        sqlx::query(
            r#"INSERT INTO events (
                   stream_id, stream_category, stream_position, event_type,
                   event_data, correlation_id, actor_type,
                   prev_event_hash, event_hash
               ) VALUES (
                   'artifact-' || $1::text, 'artifact', $2, 'ArtifactExpired',
                   jsonb_build_object(
                       'type', 'ArtifactExpired',
                       'data', jsonb_build_object('reason', $3::jsonb)
                   ),
                   gen_random_uuid(), 'system',
                   '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea,
                   '\x1111111111111111111111111111111111111111111111111111111111111111'::bytea
               )"#,
        )
        .bind(artifact)
        .bind(stream_position)
        .bind(reason)
        .execute(pool)
        .await
        .expect("append ArtifactExpired");
    }

    fn keep_last_n_reason() -> serde_json::Value {
        serde_json::json!({ "KeepLastN": { "keep": 3, "total": 10, "rank": 4 } })
    }

    fn age_exceeded_reason() -> serde_json::Value {
        serde_json::json!({
            "AgeExceeded": { "published_at": "2024-01-01T00:00:00Z", "ttl_secs": 60 }
        })
    }

    async fn seed_mutable_ref(
        pool: &PgPool,
        repo: Uuid,
        namespace: &str,
        ref_name: &str,
        kind: &str,
        hash: Option<&str>,
        version: Option<&str>,
    ) {
        sqlx::query(
            r#"INSERT INTO mutable_refs (
                   repository_id, namespace, ref_name, target_kind,
                   target_hash, target_version
               ) VALUES ($1, $2, $3, $4, $5, $6)"#,
        )
        .bind(repo)
        .bind(namespace)
        .bind(ref_name)
        .bind(kind)
        .bind(hash)
        .bind(version)
        .execute(pool)
        .await
        .expect("seed mutable ref");
    }

    async fn pending_for(pool: &PgPool, artifact: Uuid) -> PendingPurge {
        adapter(pool)
            .await
            .list_pending_purge(1000, None)
            .await
            .expect("list pending")
            .into_iter()
            .find(|p| p.artifact_id == artifact)
            .unwrap_or_else(|| panic!("{artifact} is not pending purge"))
    }

    async fn cr_rows_for(pool: &PgPool, source: Uuid) -> Vec<(String, String)> {
        sqlx::query_as(
            "SELECT kind, target_content_hash FROM content_references \
             WHERE source_artifact_id = $1 ORDER BY kind",
        )
        .bind(source)
        .fetch_all(pool)
        .await
        .expect("read cr rows")
    }

    async fn cleanup(pool: &PgPool, repo: Uuid) {
        // Events are not FK'd to repositories; sweep the artifact
        // streams explicitly, then cascade-drop the repo.
        let _ = sqlx::query(
            "DELETE FROM events WHERE stream_id IN \
             (SELECT 'artifact-' || id::text FROM artifacts WHERE repository_id = $1)",
        )
        .bind(repo)
        .execute(pool)
        .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo)
            .execute(pool)
            .await;
    }

    /// The pending set includes an artifact with `ArtifactExpired` and
    /// no `ArtifactPurged`, and EXCLUDES GC-protected quarantine states
    /// even when they have a pending `ArtifactExpired`.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn pending_set_excludes_protected_states() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;

        let ok = seed_artifact(&pool, repo, "expired-ok", HASH_A, Some("released")).await;
        append_event(&pool, ok, "ArtifactExpired", 0).await;

        // Protected: quarantined / rejected / scan_indeterminate — each
        // has a pending ArtifactExpired but MUST NOT be listed.
        for (name, status) in [
            ("quar", "quarantined"),
            ("rej", "rejected"),
            ("indet", "scan_indeterminate"),
        ] {
            let a = seed_artifact(&pool, repo, name, HASH_B, Some(status)).await;
            append_event(&pool, a, "ArtifactExpired", 0).await;
        }

        // Already-purged: ArtifactExpired + ArtifactPurged → not pending.
        let purged = seed_artifact(&pool, repo, "done", HASH_C, Some("released")).await;
        append_event(&pool, purged, "ArtifactExpired", 0).await;
        append_event(&pool, purged, "ArtifactPurged", 1).await;

        let adapter = adapter(&pool).await;
        let pending = adapter.list_pending_purge(1000, None).await.unwrap();
        let ids: Vec<Uuid> = pending.iter().map(|p| p.artifact_id).collect();

        assert!(
            ids.contains(&ok),
            "released artifact with pending expiry is in the set"
        );
        assert!(
            !ids.contains(&purged),
            "already-purged artifact is excluded"
        );
        assert_eq!(
            pending.iter().filter(|p| p.artifact_id == ok).count(),
            1,
            "no duplicates"
        );
        for protected in pending.iter() {
            assert_ne!(protected.quarantine_status, QuarantineStatus::Quarantined);
            assert_ne!(protected.quarantine_status, QuarantineStatus::Rejected);
            assert_ne!(
                protected.quarantine_status,
                QuarantineStatus::ScanIndeterminate
            );
        }

        cleanup(&pool, repo).await;
    }

    /// Both `primary_content` and `metadata_blob` rows are walked; the
    /// returned set carries one decision per distinct hash.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn primary_and_metadata_blob_both_walked() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let art = seed_artifact(&pool, repo, "two-kinds", HASH_A, Some("released")).await;
        seed_metadata_blob(&pool, art, HASH_B).await;
        // Force exactly the two rows (delete the migration auto-row).
        sqlx::query("DELETE FROM content_references WHERE source_artifact_id = $1")
            .bind(art)
            .execute(&pool)
            .await
            .unwrap();
        insert_cr(&pool, repo, art, "primary_content", HASH_A).await;
        insert_cr(&pool, repo, art, "metadata_blob", HASH_B).await;
        append_event(&pool, art, "ArtifactExpired", 0).await;

        let adapter = adapter(&pool).await;
        let mut refs = prepared(adapter.purge_artifact_refs(art, Utc::now()).await.unwrap());
        refs.sort_by(|a, b| a.content_hash.as_ref().cmp(b.content_hash.as_ref()));

        assert_eq!(
            refs.len(),
            2,
            "both primary_content and metadata_blob walked"
        );
        let by_hash: std::collections::HashMap<_, _> = refs
            .iter()
            .map(|r| (r.content_hash.as_ref().to_owned(), r.refs_remaining))
            .collect();
        // Both refs were this artifact's only references → refcount 0.
        assert_eq!(by_hash.get(HASH_A), Some(&0));
        assert_eq!(by_hash.get(HASH_B), Some(&0));
        // The rows are gone (committed transaction).
        assert!(cr_rows_for(&pool, art).await.is_empty());

        cleanup(&pool, repo).await;
    }

    /// refcount → 0 when nothing else references the hash.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn refcount_zero_when_unreferenced() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let art = seed_artifact(&pool, repo, "solo", HASH_A, Some("released")).await;
        sqlx::query("DELETE FROM content_references WHERE source_artifact_id = $1")
            .bind(art)
            .execute(&pool)
            .await
            .unwrap();
        insert_cr(&pool, repo, art, "primary_content", HASH_A).await;
        append_event(&pool, art, "ArtifactExpired", 0).await;

        let adapter = adapter(&pool).await;
        let refs = prepared(adapter.purge_artifact_refs(art, Utc::now()).await.unwrap());
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].content_hash.as_ref(), HASH_A);
        assert_eq!(refs[0].refs_remaining, 0, "no other ref → blob GC-eligible");

        cleanup(&pool, repo).await;
    }

    /// A live `oci_subject` row pointing at the same hash keeps the
    /// blob alive: cross-`kind` count is > 0 after the purge.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn live_oci_subject_keeps_blob_refs_remaining_gt_zero() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let purged = seed_artifact(&pool, repo, "purged", HASH_A, Some("released")).await;
        let other = seed_artifact(&pool, repo, "oci-live", HASH_B, Some("released")).await;
        sqlx::query("DELETE FROM content_references WHERE source_artifact_id IN ($1, $2)")
            .bind(purged)
            .bind(other)
            .execute(&pool)
            .await
            .unwrap();
        // The purged artifact's primary_content points at HASH_A.
        insert_cr(&pool, repo, purged, "primary_content", HASH_A).await;
        // A live OCI manifest (different source artifact) also points
        // at HASH_A via an oci_subject row — must keep the blob alive.
        insert_cr(&pool, repo, other, "oci_subject", HASH_A).await;
        append_event(&pool, purged, "ArtifactExpired", 0).await;

        let adapter = adapter(&pool).await;
        let refs = prepared(
            adapter
                .purge_artifact_refs(purged, Utc::now())
                .await
                .unwrap(),
        );
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].content_hash.as_ref(), HASH_A);
        assert_eq!(
            refs[0].refs_remaining, 1,
            "the live oci_subject row keeps the blob (cross-kind count)"
        );
        // The purged artifact's own primary_content row is gone; the
        // oci_subject row survives.
        assert!(cr_rows_for(&pool, purged).await.is_empty());
        assert_eq!(
            cr_rows_for(&pool, other).await,
            vec![("oci_subject".into(), HASH_A.into())]
        );

        cleanup(&pool, repo).await;
    }

    /// Idempotent re-invocation: a prior run already deleted the rows;
    /// the hash is recovered from the authoritative columns and the
    /// (now stable) cross-`kind` count is recomputed correctly.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn idempotent_reinvocation_after_rows_deleted() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let art = seed_artifact(&pool, repo, "retry", HASH_A, Some("released")).await;
        seed_metadata_blob(&pool, art, HASH_B).await;
        sqlx::query("DELETE FROM content_references WHERE source_artifact_id = $1")
            .bind(art)
            .execute(&pool)
            .await
            .unwrap();
        insert_cr(&pool, repo, art, "primary_content", HASH_A).await;
        insert_cr(&pool, repo, art, "metadata_blob", HASH_B).await;
        append_event(&pool, art, "ArtifactExpired", 0).await;

        let adapter = adapter(&pool).await;

        // First invocation deletes the rows, retires the artifact, and
        // returns both decisions.
        let first_at = Utc::now();
        let first = prepared(adapter.purge_artifact_refs(art, first_at).await.unwrap());
        assert_eq!(first.len(), 2);
        assert!(cr_rows_for(&pool, art).await.is_empty());
        let retired_at = deleted_at_of(&pool, art)
            .await
            .expect("the preparation retires the row");
        assert_eq!(retired_at.timestamp_micros(), first_at.timestamp_micros());
        let touched_at = updated_at_of(&pool, art).await;
        assert_eq!(touched_at, retired_at, "the retirement is the modification");

        // Second invocation: the edges are gone and the durable
        // worklist is the authoritative target set, so the retry reads
        // it back unchanged — both decisions, still needed to finish
        // the purge. (The `checksum_sha256` + `metadata_blob` recovery
        // path is for a projection that lost its rows before durable
        // worklists existed; a retry of this implementation never
        // reaches it.)
        let mut second = prepared(
            adapter
                .purge_artifact_refs(art, first_at + chrono::Duration::seconds(60))
                .await
                .unwrap(),
        );
        second.sort_by(|a, b| a.content_hash.as_ref().cmp(b.content_hash.as_ref()));
        assert_eq!(second.len(), 2, "idempotent retry recovers both hashes");
        // The retry re-asserts the retirement and keeps the earlier
        // timestamp: when the artifact left service is an audit fact, so
        // `COALESCE` must not let a later sweep rewrite it.
        assert_eq!(
            deleted_at_of(&pool, art).await,
            Some(retired_at),
            "a retry must not move the retirement forward"
        );
        // …and it reports no modification either: the retry changed
        // nothing about this row, and an artifact that spends several
        // sweeps deferred must not accrue a new modification time per
        // sweep for a retirement that already happened.
        assert_eq!(
            updated_at_of(&pool, art).await,
            touched_at,
            "a retry that retires nothing must not bump updated_at"
        );
        let by_hash: std::collections::HashMap<_, _> = second
            .iter()
            .map(|r| (r.content_hash.as_ref().to_owned(), r.refs_remaining))
            .collect();
        assert_eq!(by_hash.get(HASH_A), Some(&0));
        assert_eq!(by_hash.get(HASH_B), Some(&0));

        cleanup(&pool, repo).await;
    }

    /// Image-index membership (`oci_index_member`, D3): a live index
    /// keeps each of its child manifests' blobs alive under GC, and a
    /// child is freed once no index references it.
    ///
    /// The membership edges are all `source =` the index artifact,
    /// `kind =` the fixed literal `"oci_index_member"`, `target =` each
    /// child's own hash. Two children (HASH_A, HASH_C) share one
    /// `(source = index, kind = "oci_index_member")` — the widened PK
    /// `(repository_id, source_artifact_id, target_content_hash, kind)`
    /// (migration 013) makes that a true many-to-many, distinguished by
    /// `target_content_hash` (no more hash-in-`kind`). This mirrors
    /// `live_oci_subject_keeps_blob_refs_remaining_gt_zero`: the GC's
    /// cross-`kind` refcount counts the surviving index-member row
    /// against the child's hash, so purging a CHILD keeps its blob while
    /// the index still points at it, then frees it once that row is gone.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn live_index_member_keeps_child_blob_then_frees_it() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        // Two child manifest artifacts (own blobs HASH_A, HASH_C) and the
        // image-index artifact that references both (its own blob HASH_B).
        let child_a = seed_artifact(&pool, repo, "child-a", HASH_A, Some("released")).await;
        let child_c = seed_artifact(&pool, repo, "child-c", HASH_C, Some("released")).await;
        let index = seed_artifact(&pool, repo, "image-index", HASH_B, Some("released")).await;
        sqlx::query("DELETE FROM content_references WHERE source_artifact_id IN ($1, $2, $3)")
            .bind(child_a)
            .bind(child_c)
            .bind(index)
            .execute(&pool)
            .await
            .unwrap();
        // Each child's own primary_content refcount (target = child hash).
        insert_cr(&pool, repo, child_a, "primary_content", HASH_A).await;
        insert_cr(&pool, repo, child_c, "primary_content", HASH_C).await;
        // The index → children membership: TWO rows under one
        // `(source = index, kind = "oci_index_member")`, distinct only by
        // target — the widened PK admits this (the old narrow PK forced
        // a hash-in-`kind` workaround, now removed).
        insert_cr(&pool, repo, index, "oci_index_member", HASH_A).await;
        insert_cr(&pool, repo, index, "oci_index_member", HASH_C).await;
        // Sanity: N rows genuinely coexist under one (source, kind).
        assert_eq!(
            cr_rows_for(&pool, index).await,
            vec![
                ("oci_index_member".into(), HASH_A.into()),
                ("oci_index_member".into(), HASH_C.into()),
            ],
            "N children coexist under one (source = index, kind = oci_index_member)"
        );
        append_event(&pool, child_a, "ArtifactExpired", 0).await;

        let adapter = adapter(&pool).await;

        // -- Phase 1: index is live → purging child_a keeps its blob ----
        let refs = prepared(
            adapter
                .purge_artifact_refs(child_a, Utc::now())
                .await
                .unwrap(),
        );
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].content_hash.as_ref(), HASH_A);
        assert_eq!(
            refs[0].refs_remaining, 1,
            "a live index keeps the child manifest's blob (cross-kind count)"
        );
        // child_a's own primary_content row was swept; the index-member
        // rows survive (source = index, not the purged child).
        assert!(cr_rows_for(&pool, child_a).await.is_empty());
        assert_eq!(
            cr_rows_for(&pool, index).await,
            vec![
                ("oci_index_member".into(), HASH_A.into()),
                ("oci_index_member".into(), HASH_C.into()),
            ],
            "the index's oci_index_member edges survive the child purge"
        );

        // -- Phase 2: index no longer references the hash → freed ------
        // A prepared artifact's refcount decision is intentionally
        // stable in its worklist. A fresh referent for the same CAS hash
        // observes the new state after the index edges are removed.
        sqlx::query("DELETE FROM content_references WHERE source_artifact_id = $1")
            .bind(index)
            .execute(&pool)
            .await
            .unwrap();
        let later_child =
            seed_artifact(&pool, repo, "child-a-later", HASH_A, Some("released")).await;
        insert_cr(&pool, repo, later_child, "primary_content", HASH_A).await;
        let refs_after = prepared(
            adapter
                .purge_artifact_refs(later_child, Utc::now())
                .await
                .unwrap(),
        );
        assert_eq!(refs_after.len(), 1);
        assert_eq!(refs_after[0].content_hash.as_ref(), HASH_A);
        assert_eq!(
            refs_after[0].refs_remaining, 0,
            "once no index references the child, its blob is GC-eligible"
        );

        cleanup(&pool, repo).await;
    }

    /// Manifest→blob membership (`oci_config` / `oci_layer`, #46 Item 1):
    /// a live manifest keeps its config and layer blobs alive under GC,
    /// exactly like `live_index_member_keeps_child_blob_then_frees_it`
    /// keeps a child manifest alive — the GC-interaction resolution for
    /// this item (issue #46 comment "Item 1 GC-interaction — RESOLVED")
    /// requires these new kinds to behave identically to the shipped
    /// `oci_index_member` precedent: GC-active, cross-kind counted, and
    /// freed once the manifest's own edges are gone (manifest DELETE /
    /// `delete_by_source` sweeps every kind for the source, same as an
    /// index).
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn live_manifest_blob_edges_keep_config_and_layer_blobs_then_free_them() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        // A config blob (own hash HASH_A), a layer blob (own hash
        // HASH_C), and the single-image manifest artifact (own blob
        // HASH_B) that references both.
        let config = seed_artifact(&pool, repo, "config-blob", HASH_A, Some("released")).await;
        let layer = seed_artifact(&pool, repo, "layer-blob", HASH_C, Some("released")).await;
        let manifest = seed_artifact(&pool, repo, "image-manifest", HASH_B, Some("released")).await;
        sqlx::query("DELETE FROM content_references WHERE source_artifact_id IN ($1, $2, $3)")
            .bind(config)
            .bind(layer)
            .bind(manifest)
            .execute(&pool)
            .await
            .unwrap();
        // Each blob's own primary_content refcount (target = own hash).
        insert_cr(&pool, repo, config, "primary_content", HASH_A).await;
        insert_cr(&pool, repo, layer, "primary_content", HASH_C).await;
        // The manifest → blob membership: one `oci_config` row + one
        // `oci_layer` row, both `source = manifest`.
        insert_cr(&pool, repo, manifest, "oci_config", HASH_A).await;
        insert_cr(&pool, repo, manifest, "oci_layer", HASH_C).await;
        assert_eq!(
            cr_rows_for(&pool, manifest).await,
            vec![
                ("oci_config".into(), HASH_A.into()),
                ("oci_layer".into(), HASH_C.into())
            ],
            "manifest carries one oci_config row and one oci_layer row"
        );
        append_event(&pool, config, "ArtifactExpired", 0).await;
        append_event(&pool, layer, "ArtifactExpired", 0).await;

        let adapter = adapter(&pool).await;

        // -- Phase 1: manifest is live → purging config/layer keeps them -
        let config_refs = prepared(
            adapter
                .purge_artifact_refs(config, Utc::now())
                .await
                .unwrap(),
        );
        assert_eq!(config_refs.len(), 1);
        assert_eq!(config_refs[0].content_hash.as_ref(), HASH_A);
        assert_eq!(
            config_refs[0].refs_remaining, 1,
            "a live manifest keeps its config blob (cross-kind count)"
        );
        let layer_refs = prepared(
            adapter
                .purge_artifact_refs(layer, Utc::now())
                .await
                .unwrap(),
        );
        assert_eq!(layer_refs.len(), 1);
        assert_eq!(layer_refs[0].content_hash.as_ref(), HASH_C);
        assert_eq!(
            layer_refs[0].refs_remaining, 1,
            "a live manifest keeps its layer blob (cross-kind count)"
        );
        // Each blob's own primary_content row was swept; the manifest's
        // membership rows survive (source = manifest, not the purged blob).
        assert!(cr_rows_for(&pool, config).await.is_empty());
        assert!(cr_rows_for(&pool, layer).await.is_empty());
        assert_eq!(
            cr_rows_for(&pool, manifest).await,
            vec![
                ("oci_config".into(), HASH_A.into()),
                ("oci_layer".into(), HASH_C.into())
            ],
            "the manifest's oci_config/oci_layer edges survive the blob purge"
        );

        // -- Phase 2: manifest edges removed → fresh referents are free -
        // Prepared decisions remain stable in their worklists, so use
        // fresh artifact rows for the same hashes to observe the later
        // refcount after both membership edges are gone.
        sqlx::query("DELETE FROM content_references WHERE source_artifact_id = $1")
            .bind(manifest)
            .execute(&pool)
            .await
            .unwrap();
        let later_config =
            seed_artifact(&pool, repo, "config-later", HASH_A, Some("released")).await;
        let later_layer = seed_artifact(&pool, repo, "layer-later", HASH_C, Some("released")).await;
        insert_cr(&pool, repo, later_config, "primary_content", HASH_A).await;
        insert_cr(&pool, repo, later_layer, "primary_content", HASH_C).await;
        let config_refs_after = prepared(
            adapter
                .purge_artifact_refs(later_config, Utc::now())
                .await
                .unwrap(),
        );
        assert_eq!(config_refs_after.len(), 1);
        assert_eq!(config_refs_after[0].content_hash.as_ref(), HASH_A);
        assert_eq!(
            config_refs_after[0].refs_remaining, 0,
            "once the manifest is deleted, its config blob is GC-eligible"
        );
        let layer_refs_after = prepared(
            adapter
                .purge_artifact_refs(later_layer, Utc::now())
                .await
                .unwrap(),
        );
        assert_eq!(layer_refs_after.len(), 1);
        assert_eq!(layer_refs_after[0].content_hash.as_ref(), HASH_C);
        assert_eq!(
            layer_refs_after[0].refs_remaining, 0,
            "once the manifest is deleted, its layer blob is GC-eligible"
        );

        cleanup(&pool, repo).await;
    }

    /// #49 — purging a manifest/index artifact removes ITS OWN `oci_*`
    /// **source**-edges (not just `primary_content`/`metadata_blob`), so
    /// a target it references is correctly retained while ANOTHER live
    /// manifest still points at it, and correctly freed once no manifest
    /// does. Covers all four `oci_*` kinds uniformly — `oci_index_member`,
    /// `oci_subject`, `oci_config`, `oci_layer` — each in its own
    /// independent (target, manifest_1, manifest_2) triple so the fix is
    /// proven kind-by-kind, not just for one arbitrarily-chosen kind.
    ///
    /// Before the #49 fix, step 2's `DELETE ... AND kind IN
    /// ('primary_content','metadata_blob')` never touched these edges;
    /// since purge tombstones (not hard-deletes) the `artifacts` row, the
    /// `ON DELETE CASCADE` never fired either, so a purged manifest's
    /// `oci_*` edges dangled forever and permanently over-retained their
    /// targets (`refs_remaining` never reached 0). This test would have
    /// failed the second `refs_remaining == 0` assertion below against
    /// the pre-fix code — purging manifest_2 would still have reported
    /// `refs_remaining == 1` (manifest_1's dangling edge from the FIRST
    /// purge never having been swept).
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn purge_manifest_sweeps_all_oci_kinds_and_frees_target_once_unreferenced() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let adapter = adapter(&pool).await;

        // (kind, target_hash, manifest_1_own_hash, manifest_2_own_hash) —
        // one independent triple per oci_* kind.
        const CASES: [(&str, &str, &str, &str); 4] = [
            (
                "oci_index_member",
                "ec36e268b2d1bdf60cce909b3fe98bf5e5bfcde710a49609989b54ec8889a219",
                "6b4103dbacc0c272786632a3ebfa28c83cf5aa4b92a243d035be911970ab1b68",
                "2fdc5189a1993a57c847bb27a5ac3bd8e0b8ad1e663b50a7b7ca66e916a0ef48",
            ),
            (
                "oci_subject",
                "def413da534256fd1e39935baeae8fa4482bfee188c52c8972a09ec786523b74",
                "a8f449b8d736dd92c6c3bb56a17053732f893752ae1564ac9fb61e8d49e08c81",
                "3e43484e13fcadbfcc4a5281cfa128684d9077f716b4b8e890d92ae5afc21145",
            ),
            (
                "oci_config",
                "4289f601a395dc26002be9230c533f89caf989248a6993d101283b3b2523086b",
                "912d5689c5ee8473469eeaa32556d9e6c387d4c75893e13a9f16b4bfd166ca78",
                "4e6065244e725ef455b45a9b2e358ad899d78892e671edf71580472875a22fb9",
            ),
            (
                "oci_layer",
                "5bb4ff978f8fc58d81b65837626ea78ca9e4055e09abe95c40194131e00b5649",
                "1f3806ad5244aa186cddc4c05cfb9959e148a37b307f9ce12282c23f22ec71f2",
                "d3687773c21da4352074a4e231bfd48a2df7a40e10d4ed334500a2d35c154228",
            ),
        ];

        for (kind, target_hash, manifest1_hash, manifest2_hash) in CASES {
            let manifest_1 = seed_artifact(
                &pool,
                repo,
                &format!("manifest-1-{kind}"),
                manifest1_hash,
                Some("released"),
            )
            .await;
            let manifest_2 = seed_artifact(
                &pool,
                repo,
                &format!("manifest-2-{kind}"),
                manifest2_hash,
                Some("released"),
            )
            .await;
            sqlx::query("DELETE FROM content_references WHERE source_artifact_id IN ($1, $2)")
                .bind(manifest_1)
                .bind(manifest_2)
                .execute(&pool)
                .await
                .unwrap();
            // Each manifest's own primary_content refcount.
            insert_cr(&pool, repo, manifest_1, "primary_content", manifest1_hash).await;
            insert_cr(&pool, repo, manifest_2, "primary_content", manifest2_hash).await;
            // Both manifests reference the SAME target via the SAME
            // oci_* kind — the scenario `content_references` widened PK
            // exists for (two sources, one target, one kind).
            insert_cr(&pool, repo, manifest_1, kind, target_hash).await;
            insert_cr(&pool, repo, manifest_2, kind, target_hash).await;
            append_event(&pool, manifest_1, "ArtifactExpired", 0).await;
            append_event(&pool, manifest_2, "ArtifactExpired", 0).await;

            // -- Purge manifest_1: manifest_2's edge keeps the target alive --
            let refs_1 = prepared(
                adapter
                    .purge_artifact_refs(manifest_1, Utc::now())
                    .await
                    .unwrap(),
            );
            let target_ref_1 = refs_1
                .iter()
                .find(|r| r.content_hash.as_ref() == target_hash)
                .unwrap_or_else(|| {
                    panic!("kind {kind}: purging manifest_1 must report the target hash")
                });
            assert_eq!(
                target_ref_1.refs_remaining, 1,
                "kind {kind}: manifest_2's live {kind} edge must keep the target retained \
                 after manifest_1 is purged"
            );
            // manifest_1's OWN oci_* source-edge is gone (the #49 fix) —
            // not just its primary_content row.
            assert!(
                cr_rows_for(&pool, manifest_1).await.is_empty(),
                "kind {kind}: purging manifest_1 must sweep ALL its source-edges, \
                 including its {kind} edge, not just primary_content"
            );
            // manifest_2's edge survives untouched.
            assert_eq!(
                cr_rows_for(&pool, manifest_2).await,
                vec![
                    (kind.to_string(), target_hash.to_string()),
                    ("primary_content".to_string(), manifest2_hash.to_string()),
                ],
                "kind {kind}: manifest_2's own edges must be untouched by manifest_1's purge"
            );

            // -- Purge manifest_2: no live source-edge remains → freed --
            let refs_2 = prepared(
                adapter
                    .purge_artifact_refs(manifest_2, Utc::now())
                    .await
                    .unwrap(),
            );
            let target_ref_2 = refs_2
                .iter()
                .find(|r| r.content_hash.as_ref() == target_hash)
                .unwrap_or_else(|| {
                    panic!("kind {kind}: purging manifest_2 must report the target hash")
                });
            assert_eq!(
                target_ref_2.refs_remaining, 0,
                "kind {kind}: once BOTH manifests are purged, the target must be \
                 GC-eligible (refs_remaining == 0) — the #49 leak this test guards against"
            );
        }

        cleanup(&pool, repo).await;
    }

    /// The worklist, not the deleted edge set, drives every retry. An
    /// OCI child target therefore survives preparation and remains
    /// outstanding after another hash has completed.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn retry_preserves_outstanding_oci_child_hash() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let artifact = seed_artifact(&pool, repo, "oci-retry", HASH_A, Some("released")).await;
        sqlx::query("DELETE FROM content_references WHERE source_artifact_id = $1")
            .bind(artifact)
            .execute(&pool)
            .await
            .unwrap();
        insert_cr(&pool, repo, artifact, "primary_content", HASH_A).await;
        insert_cr(&pool, repo, artifact, "oci_layer", HASH_C).await;
        append_event(&pool, artifact, "ArtifactExpired", 0).await;

        let adapter = adapter(&pool).await;
        let worklist = prepared(
            adapter
                .purge_artifact_refs(artifact, Utc::now())
                .await
                .unwrap(),
        );
        assert_eq!(worklist.len(), 2);
        assert!(cr_rows_for(&pool, artifact).await.is_empty());

        adapter
            .mark_purge_ref_complete(artifact, &HASH_A.parse().unwrap(), Utc::now())
            .await
            .unwrap();
        let retry = prepared(
            adapter
                .purge_artifact_refs(artifact, Utc::now())
                .await
                .unwrap(),
        );
        let primary = retry
            .iter()
            .find(|item| item.content_hash.as_ref() == HASH_A)
            .unwrap();
        let child = retry
            .iter()
            .find(|item| item.content_hash.as_ref() == HASH_C)
            .unwrap();
        assert!(primary.completed);
        assert!(!child.completed);
        assert_eq!(child.refs_remaining, 0);

        cleanup(&pool, repo).await;
    }

    /// **What a reader gets inside the window, pinned.** The sweep
    /// deletes the blob, the terminal transition is interrupted, and the
    /// artifact ends the run with its bytes gone and its work item
    /// pending — the state the old order served from a live row.
    ///
    /// Measured before this change, the reader resolved the row, passed
    /// `Artifact::is_downloadable` (which has no expiry term, by design)
    /// and then failed in CAS: `AppError::Storage("not found: content
    /// …")`, an opaque `500` on something the API still advertised, and
    /// a `DownloadResult::StorageError` in the metrics for a routine,
    /// expected race. With the retirement written by the preparation the
    /// row no longer resolves at all — `find_by_id` filters
    /// `deleted_at IS NULL` — so the answer is `NotFound`, the honest
    /// `404` (`hort_http_core::error`'s `not_found_is_404` pins that
    /// hop; `storage_error_is_500` pins the one this replaces).
    ///
    /// The `Storage` assertion is the load-bearing half: `NotFound`
    /// alone could be reached by an artifact that was never there.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn a_half_purged_artifact_is_gone_to_the_reader_not_broken() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let temp = tempfile::tempdir().unwrap();
        let filesystem = hort_adapters_storage::FilesystemStorage::new(temp.path().to_path_buf());
        let put = filesystem
            .put(Box::new(std::io::Cursor::new(b"foo".to_vec())))
            .await
            .unwrap();
        assert_eq!(put.hash.as_ref(), HASH_C);

        let repo = seed_repo(&pool).await;
        let artifact = seed_artifact(&pool, repo, "window", HASH_C, Some("released")).await;
        sqlx::query("DELETE FROM content_references WHERE source_artifact_id = $1")
            .bind(artifact)
            .execute(&pool)
            .await
            .unwrap();
        insert_cr(&pool, repo, artifact, "primary_content", HASH_C).await;
        append_event(&pool, artifact, "ArtifactExpired", 0).await;

        let event_store = Arc::new(PgEventStore::new(pool.clone()).await.unwrap());
        let gc = Arc::new(PgPurgeGcPort::new(pool.clone(), Arc::clone(&event_store)));
        let storage = Arc::new(filesystem);
        let use_case = PurgeUseCase::new(
            Arc::clone(&gc) as Arc<dyn PurgeGcPort>,
            Arc::clone(&storage) as Arc<dyn StoragePort>,
            Arc::new(ConvergedGate),
        );

        // Abort the run after the bytes are already gone: the storage
        // delete and its checkpoint both succeed, the terminal
        // transition does not.
        gc.interrupt_next_terminal_transition();
        let aborted = use_case.process_expired(Utc::now()).await.unwrap();
        assert_eq!(aborted.errors, 1);
        assert_eq!(aborted.purged_events, 0);
        assert!(
            !storage.exists(&put.hash).await.unwrap(),
            "the window needs the bytes actually gone"
        );

        let download = hort_app::use_cases::artifact_use_case::ArtifactUseCase::new(
            Arc::new(crate::artifact_repo::PgArtifactRepository::new(
                pool.clone(),
                Arc::clone(&event_store),
            )),
            Arc::clone(&storage) as Arc<dyn StoragePort>,
            Arc::new(crate::repository_repo::PgRepositoryRepository::new(
                pool.clone(),
            )),
            true,
        );
        match download.download(artifact, None).await {
            Err(hort_app::error::AppError::Domain(DomainError::NotFound { entity, .. })) => {
                assert_eq!(entity, "Artifact");
            }
            Err(other) => {
                panic!("a purged artifact must read as gone, not as a server fault: {other:?}")
            }
            Ok(_) => panic!("a purged artifact must not serve a stream"),
        }

        // And it is still the next sweep's work, so the window closes
        // by itself.
        let resumed = use_case.process_expired(Utc::now()).await.unwrap();
        assert_eq!(resumed.errors, 0);
        assert_eq!(resumed.purged_events, 1);

        cleanup(&pool, repo).await;
    }

    /// A failed OCI-child delete withholds the whole artifact-level
    /// transition. The next sweep reads the child from the persisted
    /// worklist, deletes it, and commits both terminal events together.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn oci_child_delete_failure_retries_and_completes_entire_artifact() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let temp = tempfile::tempdir().unwrap();
        let filesystem = hort_adapters_storage::FilesystemStorage::new(temp.path().to_path_buf());
        let primary_put = filesystem
            .put(Box::new(std::io::Cursor::new(b"foo".to_vec())))
            .await
            .unwrap();
        let child_put = filesystem
            .put(Box::new(std::io::Cursor::new(Vec::new())))
            .await
            .unwrap();
        assert_eq!(primary_put.hash.as_ref(), HASH_C);
        assert_eq!(child_put.hash.as_ref(), HASH_A);

        let repo = seed_repo(&pool).await;
        let artifact = seed_artifact(&pool, repo, "oci-failure", HASH_C, Some("released")).await;
        sqlx::query("DELETE FROM content_references WHERE source_artifact_id = $1")
            .bind(artifact)
            .execute(&pool)
            .await
            .unwrap();
        insert_cr(&pool, repo, artifact, "primary_content", HASH_C).await;
        insert_cr(&pool, repo, artifact, "oci_layer", HASH_A).await;
        append_event(&pool, artifact, "ArtifactExpired", 0).await;

        let event_store = Arc::new(PgEventStore::new(pool.clone()).await.unwrap());
        let gc = Arc::new(PgPurgeGcPort::new(pool.clone(), event_store));
        let storage = Arc::new(FailDeleteOnceStorage::new(
            filesystem,
            child_put.hash.clone(),
        ));
        let use_case = PurgeUseCase::new(gc, storage.clone(), Arc::new(ConvergedGate));

        let first = use_case.process_expired(Utc::now()).await.unwrap();
        assert_eq!(first.errors, 1);
        assert_eq!(first.purged_events, 0);
        // The aborted run leaves the artifact RETIRED with a blob still
        // standing, which is the safe half of the pair: the preparation
        // wrote `deleted_at` before the first delete, so nothing serves
        // the hash whose bytes are already gone.
        let deleted_at: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT deleted_at FROM artifacts WHERE id = $1")
                .bind(artifact)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(deleted_at.is_some(), "retired by the preparation");
        let first_events: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM events WHERE stream_id = $1 AND event_type = 'ArtifactPurged'",
        )
        .bind(StreamId::artifact(artifact).to_string())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(first_events, 0);
        // …and the work item is still pending, because membership never
        // looked at `deleted_at`. That is what lets the retry below
        // finish the job with no operator step.
        assert_eq!(
            adapter(&pool)
                .await
                .list_pending_purge(10, None)
                .await
                .unwrap()
                .len(),
            1,
            "a retired-but-unpurged artifact is still the next sweep's work"
        );

        let retry = use_case.process_expired(Utc::now()).await.unwrap();
        assert_eq!(retry.errors, 0);
        assert_eq!(retry.purged_events, 2);
        assert!(!storage.exists(&primary_put.hash).await.unwrap());
        assert!(!storage.exists(&child_put.hash).await.unwrap());
        let deleted_at: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT deleted_at FROM artifacts WHERE id = $1")
                .bind(artifact)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(deleted_at.is_some());
        let terminal_events: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM events WHERE stream_id = $1 AND event_type = 'ArtifactPurged'",
        )
        .bind(StreamId::artifact(artifact).to_string())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(terminal_events, 2);

        cleanup(&pool, repo).await;
    }

    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn incomplete_or_unknown_work_cannot_reach_terminal_transition() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let artifact = seed_artifact(&pool, repo, "incomplete", HASH_A, Some("released")).await;
        sqlx::query("DELETE FROM content_references WHERE source_artifact_id = $1")
            .bind(artifact)
            .execute(&pool)
            .await
            .unwrap();
        insert_cr(&pool, repo, artifact, "primary_content", HASH_A).await;
        append_event(&pool, artifact, "ArtifactExpired", 0).await;

        let adapter = adapter(&pool).await;
        let refs = prepared(
            adapter
                .purge_artifact_refs(artifact, Utc::now())
                .await
                .unwrap(),
        );
        let retired_at = Utc::now();
        let error = adapter
            .complete_artifact_purge(
                artifact,
                retired_at,
                terminal_batch(artifact, &refs, retired_at),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("incomplete storage work"));
        let unknown: ContentHash = HASH_C.parse().unwrap();
        assert!(adapter
            .mark_purge_ref_complete(artifact, &unknown, retired_at)
            .await
            .is_err());

        // What the refused transition withholds is the terminal
        // *event*. The retirement is not its to withhold — the
        // preparation above already wrote it, which is the point of the
        // order.
        let deleted_at: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT deleted_at FROM artifacts WHERE id = $1")
                .bind(artifact)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(deleted_at.is_some(), "retired by the preparation");
        let purged_events: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM events WHERE stream_id = $1 AND event_type = 'ArtifactPurged'",
        )
        .bind(StreamId::artifact(artifact).to_string())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(purged_events, 0);

        cleanup(&pool, repo).await;
    }

    /// The terminal transition is one commit. The injected interruption
    /// happens after the append was staged and proves that dropping the
    /// transaction exposes none of its writes — no `ArtifactPurged`,
    /// and no touch to the `deleted_at` the *preparation* wrote, which
    /// is captured first here precisely so an unchanged value is a
    /// measured fact rather than an absence that proves nothing.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn interrupted_terminal_transition_exposes_no_event_and_leaves_the_retirement_alone() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let artifact = seed_artifact(&pool, repo, "atomic", HASH_A, Some("released")).await;
        sqlx::query("DELETE FROM content_references WHERE source_artifact_id = $1")
            .bind(artifact)
            .execute(&pool)
            .await
            .unwrap();
        insert_cr(&pool, repo, artifact, "primary_content", HASH_A).await;
        append_event(&pool, artifact, "ArtifactExpired", 0).await;

        let adapter = adapter(&pool).await;
        let prepared_at = Utc::now();
        let refs = prepared(
            adapter
                .purge_artifact_refs(artifact, prepared_at)
                .await
                .unwrap(),
        );
        let retired_by_prepare: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT deleted_at FROM artifacts WHERE id = $1")
                .bind(artifact)
                .fetch_one(&pool)
                .await
                .unwrap();
        // Postgres `timestamptz` keeps microseconds, so compare at that
        // resolution — the claim is that the retirement carries the
        // caller's injected sweep clock, not a server-side `now()`.
        assert_eq!(
            retired_by_prepare.map(|t| t.timestamp_micros()),
            Some(prepared_at.timestamp_micros())
        );
        adapter
            .mark_purge_ref_complete(artifact, &refs[0].content_hash, Utc::now())
            .await
            .unwrap();
        let retired_at = Utc::now();
        adapter.interrupt_next_terminal_transition();
        let error = adapter
            .complete_artifact_purge(
                artifact,
                retired_at,
                terminal_batch(artifact, &refs, retired_at),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("injected interruption"));

        let deleted_at: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT deleted_at FROM artifacts WHERE id = $1")
                .bind(artifact)
                .fetch_one(&pool)
                .await
                .unwrap();
        let purged_events: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM events WHERE stream_id = $1 AND event_type = 'ArtifactPurged'",
        )
        .bind(StreamId::artifact(artifact).to_string())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            deleted_at, retired_by_prepare,
            "the rolled-back transition must not have moved the retirement"
        );
        assert_eq!(purged_events, 0);

        cleanup(&pool, repo).await;
    }

    /// Even when another referent keeps the bytes, the expired artifact
    /// retires, its terminal event keeps retention attribution, and a
    /// reconcile pass does not recreate the removed source edge.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn shared_blob_purge_retires_projection_and_reconcile_leaves_it_retired() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let expired = seed_artifact(&pool, repo, "expired-shared", HASH_A, Some("released")).await;
        let live = seed_artifact(&pool, repo, "live-shared", HASH_B, Some("released")).await;
        sqlx::query("DELETE FROM content_references WHERE source_artifact_id IN ($1, $2)")
            .bind(expired)
            .bind(live)
            .execute(&pool)
            .await
            .unwrap();
        insert_cr(&pool, repo, expired, "primary_content", HASH_A).await;
        insert_cr(&pool, repo, live, "oci_subject", HASH_A).await;
        append_event(&pool, expired, "ArtifactExpired", 0).await;

        let adapter = adapter(&pool).await;
        let refs = prepared(
            adapter
                .purge_artifact_refs(expired, Utc::now())
                .await
                .unwrap(),
        );
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].refs_remaining, 1);
        // The same question asked INSIDE the purge window — after the
        // preparation, before the terminal transition. It is the
        // retirement the preparation just wrote that answers it: while
        // the row stayed live until the end of the sweep, a reconcile
        // landing here saw an artifact with no `primary_content` edge
        // and minted one back.
        assert!(
            reconcile_proposes_no_repair_for(&pool, repo, expired).await,
            "a reconcile inside the purge window must not re-mint the edge \
             the preparation deleted"
        );
        adapter
            .mark_purge_ref_complete(expired, &refs[0].content_hash, Utc::now())
            .await
            .unwrap();
        let retired_at = Utc::now();
        adapter
            .complete_artifact_purge(
                expired,
                retired_at,
                terminal_batch(expired, &refs, retired_at),
            )
            .await
            .unwrap();

        let artifact_repo = crate::artifact_repo::PgArtifactRepository::new(
            pool.clone(),
            adapter.event_store.clone(),
        );
        assert!(matches!(
            artifact_repo.find_by_id(expired).await,
            Err(DomainError::NotFound { .. })
        ));
        let historical: crate::mappers::ArtifactRow = sqlx::query_as(
            r#"
            SELECT id, repository_id, name, name_as_published, version, path,
                   size_bytes, checksum_sha256, checksum_sha1, checksum_md5,
                   content_type, storage_key, quarantine_status,
                   quarantine_window_start, upstream_published_at, uploaded_by,
                   created_at, updated_at, deleted_at
              FROM artifacts WHERE id = $1
            "#,
        )
        .bind(expired)
        .fetch_one(&pool)
        .await
        .unwrap();
        let historical = hort_domain::entities::artifact::Artifact::try_from(historical).unwrap();
        assert!(!historical.is_downloadable());

        let actor_type: String = sqlx::query_scalar(
            "SELECT actor_type FROM events \
             WHERE stream_id = $1 AND event_type = 'ArtifactPurged'",
        )
        .bind(StreamId::artifact(expired).to_string())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(actor_type, "retention_scheduler");
        let deleted_events: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM events \
             WHERE stream_id = $1 AND event_type = 'ArtifactDeleted'",
        )
        .bind(StreamId::artifact(expired).to_string())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(deleted_events, 0);

        assert!(
            reconcile_proposes_no_repair_for(&pool, repo, expired).await,
            "a purged artifact's edge is not re-minted"
        );
        assert_eq!(
            cr_rows_for(&pool, live).await,
            vec![("oci_subject".into(), HASH_A.into())]
        );

        cleanup(&pool, repo).await;
    }

    /// A user-facing delete can land between the expiry decision and the
    /// purge sweep — the pending-purge set filters on the two events and
    /// the quarantine status only, so the artifact is still enumerated
    /// and its storage work still runs. The terminal transition must
    /// then succeed over the already-retired row: a guard demanding
    /// `deleted_at IS NULL` would fail identically on every retry,
    /// stranding an artifact whose blobs are gone, whose row lives, and
    /// whose stream carries no terminal event. The delete's timestamp
    /// survives the purge — it records when the artifact left service.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn purge_completes_over_a_row_already_retired_by_the_delete_path() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let art = seed_artifact(&pool, repo, "hand-deleted", HASH_A, Some("released")).await;
        sqlx::query("DELETE FROM content_references WHERE source_artifact_id = $1")
            .bind(art)
            .execute(&pool)
            .await
            .unwrap();
        insert_cr(&pool, repo, art, "primary_content", HASH_A).await;
        append_event(&pool, art, "ArtifactExpired", 0).await;

        let adapter = adapter(&pool).await;

        // The operator deletes the artifact through the normal verb,
        // after it expired and before the sweep runs.
        let artifact_repo = crate::artifact_repo::PgArtifactRepository::new(
            pool.clone(),
            adapter.event_store.clone(),
        );
        artifact_repo
            .delete(
                art,
                hort_domain::events::Actor::Api(hort_domain::events::ApiActor {
                    user_id: Uuid::new_v4(),
                }),
            )
            .await
            .unwrap();
        let user_deleted_at: DateTime<Utc> =
            sqlx::query_scalar("SELECT deleted_at FROM artifacts WHERE id = $1")
                .bind(art)
                .fetch_one(&pool)
                .await
                .unwrap();

        // Still pending: the delete verb retires the projection, it does
        // not remove the bytes.
        assert!(adapter
            .list_pending_purge(1000, None)
            .await
            .unwrap()
            .iter()
            .any(|p| p.artifact_id == art));

        let refs = prepared(adapter.purge_artifact_refs(art, Utc::now()).await.unwrap());
        assert_eq!(refs.len(), 1);
        adapter
            .mark_purge_ref_complete(art, &refs[0].content_hash, Utc::now())
            .await
            .unwrap();
        let retired_at = user_deleted_at + chrono::Duration::seconds(60);
        adapter
            .complete_artifact_purge(art, retired_at, terminal_batch(art, &refs, retired_at))
            .await
            .unwrap();

        let purged_events: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM events WHERE stream_id = $1 AND event_type = 'ArtifactPurged'",
        )
        .bind(StreamId::artifact(art).to_string())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(purged_events, 1, "the terminal event is appended");
        let outstanding: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM artifact_purge_worklist WHERE artifact_id = $1",
        )
        .bind(art)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(outstanding, 0, "the worklist is cleared");
        assert!(
            !adapter
                .list_pending_purge(1000, None)
                .await
                .unwrap()
                .iter()
                .any(|p| p.artifact_id == art),
            "the artifact leaves the pending set instead of stalling forever"
        );

        let deleted_at: DateTime<Utc> =
            sqlx::query_scalar("SELECT deleted_at FROM artifacts WHERE id = $1")
                .bind(art)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            deleted_at, user_deleted_at,
            "the earlier retirement timestamp is the audit fact and is kept"
        );

        cleanup(&pool, repo).await;
    }

    /// Retiring the old row frees the live path key. Re-pushing the
    /// same bytes performs a fresh CAS write, creates a new row, and
    /// makes those bytes readable again.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn purge_then_repush_same_path_writes_and_fetches_bytes() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let temp = tempfile::tempdir().unwrap();
        let storage = hort_adapters_storage::FilesystemStorage::new(temp.path().to_path_buf());
        let bytes = b"hello world".to_vec();
        let first_put = storage
            .put(Box::new(std::io::Cursor::new(bytes.clone())))
            .await
            .unwrap();
        assert_eq!(first_put.hash.as_ref(), HASH_B);

        let repo = seed_repo(&pool).await;
        let old = seed_artifact(&pool, repo, "repush", HASH_B, Some("released")).await;
        let path: String = sqlx::query_scalar("SELECT path FROM artifacts WHERE id = $1")
            .bind(old)
            .fetch_one(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM content_references WHERE source_artifact_id = $1")
            .bind(old)
            .execute(&pool)
            .await
            .unwrap();
        insert_cr(&pool, repo, old, "primary_content", HASH_B).await;
        append_event(&pool, old, "ArtifactExpired", 0).await;

        let adapter = adapter(&pool).await;
        let refs = prepared(adapter.purge_artifact_refs(old, Utc::now()).await.unwrap());
        storage.delete(&refs[0].content_hash).await.unwrap();
        adapter
            .mark_purge_ref_complete(old, &refs[0].content_hash, Utc::now())
            .await
            .unwrap();
        let retired_at = Utc::now();
        adapter
            .complete_artifact_purge(old, retired_at, terminal_batch(old, &refs, retired_at))
            .await
            .unwrap();
        assert!(!storage.exists(&refs[0].content_hash).await.unwrap());
        let artifact_repo = crate::artifact_repo::PgArtifactRepository::new(
            pool.clone(),
            adapter.event_store.clone(),
        );
        assert!(artifact_repo
            .find_by_path(repo, &path)
            .await
            .unwrap()
            .is_none());

        let second_put = storage
            .put(Box::new(std::io::Cursor::new(bytes.clone())))
            .await
            .unwrap();
        assert_eq!(second_put.hash, refs[0].content_hash);
        let fresh = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO artifacts (
                id, repository_id, name, name_as_published, version, path,
                size_bytes, checksum_sha256, content_type, storage_key,
                quarantine_status
            ) VALUES (
                $1, $2, 'repush', 'repush', '1.0.0', $3,
                $4, $5, 'application/octet-stream', $3, 'released'
            )
            "#,
        )
        .bind(fresh)
        .bind(repo)
        .bind(&path)
        .bind(i64::try_from(bytes.len()).unwrap())
        .bind(second_put.hash.as_ref())
        .execute(&pool)
        .await
        .unwrap();

        let live = artifact_repo
            .find_by_path(repo, &path)
            .await
            .unwrap()
            .expect("re-pushed path is live");
        assert_eq!(live.id, fresh);
        assert_ne!(fresh, old);
        let rows_at_path: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM artifacts WHERE repository_id = $1 AND path = $2",
        )
        .bind(repo)
        .bind(&path)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(rows_at_path, 2);
        let mut reader = storage.get(&second_put.hash).await.unwrap();
        let mut fetched = Vec::new();
        reader.read_to_end(&mut fetched).await.unwrap();
        assert_eq!(fetched, bytes);

        cleanup(&pool, repo).await;
    }

    /// A hard-deleted artifact row (FK cascade already swept its refs)
    /// is a clean no-op — nothing left to decrement.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn missing_artifact_row_is_a_noop() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let adapter = adapter(&pool).await;
        assert_eq!(
            adapter
                .purge_artifact_refs(Uuid::new_v4(), Utc::now())
                .await
                .unwrap(),
            PurgePreparation::NoArtifact,
            "no artifact row → nothing to purge, and it says so in its own \
             value: an empty worklist is a different fact and the sweep \
             logs it differently"
        );
    }

    // -- tag exemption: the facts the purge sweep reports ----------------

    /// Walk the interval the two cron sweeps leave open. At 03:00 the
    /// evaluator expired an untagged artifact under `KeepLastN`; at
    /// 03:30 an operator tagged it; the purge runs at 04:00 and nothing
    /// re-ran the predicate. The work-set read is what has to notice —
    /// the page row covers the gap between the two *sweeps*, and the
    /// re-read under the artifact lock covers the gap inside this one.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn a_tag_set_after_expiry_flips_the_pending_row() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let art = seed_artifact(&pool, repo, "interval", HASH_A, Some("released")).await;
        append_expired_with_reason(&pool, art, 0, keep_last_n_reason()).await;

        // 03:00 — expired, nothing points at it.
        let before = pending_for(&pool, art).await;
        assert!(!before.tag_targeted);
        assert!(before.expired_only_by_keep_last_n);

        // 03:30 — an operator tags it.
        seed_mutable_ref(
            &pool,
            repo,
            "interval",
            "latest",
            "hash",
            Some(HASH_A),
            None,
        )
        .await;

        // 04:00 — the purge sweep reads the work set.
        let after = pending_for(&pool, art).await;
        assert!(
            after.tag_targeted,
            "the ref set after the expiry must be visible to the purge"
        );
        assert!(after.expired_only_by_keep_last_n);

        cleanup(&pool, repo).await;
    }

    /// The version target kind — the npm dist-tag shape. A hash-only
    /// reading reports `false` here.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn pending_tag_targeted_covers_the_version_target_kind() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let art = seed_artifact(&pool, repo, "dist-tagged", HASH_A, Some("released")).await;
        append_expired_with_reason(&pool, art, 0, keep_last_n_reason()).await;
        // `seed_artifact` stores version '1.0.0' under name = namespace.
        seed_mutable_ref(
            &pool,
            repo,
            "dist-tagged",
            "latest",
            "version",
            None,
            Some("1.0.0"),
        )
        .await;

        assert!(pending_for(&pool, art).await.tag_targeted);

        cleanup(&pool, repo).await;
    }

    /// Identical content tagged in a *different* repository must not
    /// exempt this one — CAS shares hashes across repositories.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn pending_tag_targeted_is_repository_scoped() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let elsewhere = seed_repo(&pool).await;
        let art = seed_artifact(&pool, repo, "shared", HASH_A, Some("released")).await;
        append_expired_with_reason(&pool, art, 0, keep_last_n_reason()).await;
        // Same bytes, same name, same version — tagged next door.
        seed_mutable_ref(
            &pool,
            elsewhere,
            "shared",
            "latest",
            "hash",
            Some(HASH_A),
            None,
        )
        .await;
        seed_mutable_ref(
            &pool,
            elsewhere,
            "shared",
            "dist",
            "version",
            None,
            Some("1.0.0"),
        )
        .await;

        assert!(!pending_for(&pool, art).await.tag_targeted);

        cleanup(&pool, repo).await;
        cleanup(&pool, elsewhere).await;
    }

    /// A non-`KeepLastN` expiry clears the flag: an age- or
    /// security-driven decision is not countermanded by a tag.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn an_age_expiry_is_not_keep_last_n_only() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let aged = seed_artifact(&pool, repo, "aged", HASH_A, Some("released")).await;
        append_expired_with_reason(&pool, aged, 0, age_exceeded_reason()).await;
        // Both reasons on one stream: the age decision still stands.
        let both = seed_artifact(&pool, repo, "both", HASH_B, Some("released")).await;
        append_expired_with_reason(&pool, both, 0, keep_last_n_reason()).await;
        append_expired_with_reason(&pool, both, 1, age_exceeded_reason()).await;

        assert!(!pending_for(&pool, aged).await.expired_only_by_keep_last_n);
        assert!(!pending_for(&pool, both).await.expired_only_by_keep_last_n);

        cleanup(&pool, repo).await;
    }

    /// End-to-end through the real use case: the tagged artifact keeps
    /// its blob and its row; an identical untagged one is purged.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn purge_sweep_skips_the_tagged_artifact_and_purges_its_sibling() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let tagged = seed_artifact(&pool, repo, "keeper", HASH_A, Some("released")).await;
        let doomed = seed_artifact(&pool, repo, "goner", HASH_B, Some("released")).await;
        for art in [tagged, doomed] {
            sqlx::query("DELETE FROM content_references WHERE source_artifact_id = $1")
                .bind(art)
                .execute(&pool)
                .await
                .unwrap();
            append_expired_with_reason(&pool, art, 0, keep_last_n_reason()).await;
        }
        insert_cr(&pool, repo, tagged, "primary_content", HASH_A).await;
        insert_cr(&pool, repo, doomed, "primary_content", HASH_B).await;
        seed_mutable_ref(&pool, repo, "keeper", "latest", "hash", Some(HASH_A), None).await;

        let tmp = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(hort_adapters_storage::FilesystemStorage::new(
            tmp.path().to_path_buf(),
        ));
        let uc = PurgeUseCase::new(
            Arc::new(adapter(&pool).await),
            storage,
            Arc::new(ConvergedGate),
        );

        let summary = uc.process_expired(Utc::now()).await.expect("sweep runs");

        assert_eq!(summary.skipped_tag_exempt, 1);
        // The tagged artifact was never even prepared: its reference
        // edge is intact and its row is still live.
        assert_eq!(cr_rows_for(&pool, tagged).await.len(), 1);
        assert!(cr_rows_for(&pool, doomed).await.is_empty());
        let tagged_deleted_at: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT deleted_at FROM artifacts WHERE id = $1")
                .bind(tagged)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(tagged_deleted_at.is_none(), "the tag target stays live");
        let doomed_deleted_at: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT deleted_at FROM artifacts WHERE id = $1")
                .bind(doomed)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            doomed_deleted_at.is_some(),
            "the untagged sibling is purged"
        );

        cleanup(&pool, repo).await;
    }

    // =====================================================================
    // The caller-facing delete as a byte-release work item
    // =====================================================================

    /// Shorthand for the caller-facing soft delete through the real
    /// verb, returning the `deleted_at` it wrote.
    async fn soft_delete(pool: &PgPool, adapter: &PgPurgeGcPort, art: Uuid) -> DateTime<Utc> {
        let artifact_repo = crate::artifact_repo::PgArtifactRepository::new(
            pool.clone(),
            adapter.event_store.clone(),
        );
        artifact_repo
            .delete(
                art,
                hort_domain::events::Actor::Api(hort_domain::events::ApiActor {
                    user_id: Uuid::new_v4(),
                }),
            )
            .await
            .expect("soft delete");
        sqlx::query_scalar("SELECT deleted_at FROM artifacts WHERE id = $1")
            .bind(art)
            .fetch_one(pool)
            .await
            .expect("deleted_at")
    }

    /// An `ArtifactDeleted` is a byte-release work item in its own right:
    /// the artifact enters the pending set with no expiry decision on its
    /// stream at all, flagged so the `KeepLastN` tag exemption cannot
    /// claim it. An already-purged delete leaves the set, and a
    /// GC-protected status keeps evidence out of the destructive path
    /// even when a caller deleted it.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn pending_set_admits_a_caller_deleted_artifact_and_flags_it() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let adapter = Arc::new(adapter(&pool).await);

        // Delete only — no ArtifactExpired anywhere on the stream.
        let deleted = seed_artifact(&pool, repo, "deleted", HASH_A, Some("released")).await;
        soft_delete(&pool, &adapter, deleted).await;

        // Expiry only — the pre-existing work item, for contrast.
        let expired = seed_artifact(&pool, repo, "expired", HASH_B, Some("released")).await;
        append_expired_with_reason(&pool, expired, 0, age_exceeded_reason()).await;

        // Deleted and already collected: the terminal event ends the item.
        let done = seed_artifact(&pool, repo, "done", HASH_C, Some("released")).await;
        soft_delete(&pool, &adapter, done).await;
        append_event(&pool, done, "ArtifactPurged", 50).await;

        // Evidence a caller deleted: the row retires, the bytes stay.
        let rejected = seed_artifact(&pool, repo, "rejected", HASH_B, Some("rejected")).await;
        soft_delete(&pool, &adapter, rejected).await;

        let pending = adapter.list_pending_purge(1000, None).await.unwrap();
        let ids: Vec<Uuid> = pending.iter().map(|p| p.artifact_id).collect();
        assert!(
            ids.contains(&deleted),
            "a caller-deleted artifact is pending byte release"
        );
        assert!(ids.contains(&expired), "an expiry is still pending");
        assert!(
            !ids.contains(&done),
            "ArtifactPurged terminates a delete work item too"
        );
        assert!(
            !ids.contains(&rejected),
            "inv1: deleting evidence must not offer it to the destructive path"
        );

        let row = pending_for(&pool, deleted).await;
        assert!(row.user_deleted);
        assert!(
            row.expired_only_by_keep_last_n,
            "vacuously true with no expiry decision — which is exactly why \
             the tag exemption needs user_deleted as a second fact"
        );
        assert!(!pending_for(&pool, expired).await.user_deleted);

        cleanup(&pool, repo).await;
    }

    /// End-to-end through the real delete verb and the real sweep: the
    /// source edge is released, the refcount falls to zero, and the blob
    /// is gone. The delete's own timestamp survives the purge — it is
    /// when the artifact left service.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn a_soft_delete_releases_the_edge_and_collects_the_blob() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        let storage = Arc::new(hort_adapters_storage::FilesystemStorage::new(
            tmp.path().to_path_buf(),
        ));
        let put = storage
            .put(Box::new(std::io::Cursor::new(b"hello world".to_vec())))
            .await
            .unwrap();
        assert_eq!(put.hash.as_ref(), HASH_B);

        let repo = seed_repo(&pool).await;
        let art = seed_artifact(&pool, repo, "byte-release", HASH_B, Some("released")).await;
        sqlx::query("DELETE FROM content_references WHERE source_artifact_id = $1")
            .bind(art)
            .execute(&pool)
            .await
            .unwrap();
        insert_cr(&pool, repo, art, "primary_content", HASH_B).await;

        let adapter = Arc::new(adapter(&pool).await);
        let deleted_at = soft_delete(&pool, &adapter, art).await;
        assert_eq!(
            cr_rows_for(&pool, art).await.len(),
            1,
            "the delete itself leaves the edge to the sweep, which is the \
             only step that records the target in a durable worklist"
        );

        let uc = PurgeUseCase::new(adapter.clone(), storage.clone(), Arc::new(ConvergedGate));
        let summary = uc.process_expired(Utc::now()).await.expect("sweep runs");

        assert_eq!(summary.user_deletes_visited, 1);
        assert_eq!(summary.blobs_deleted, 1);
        assert_eq!(summary.skipped_tag_exempt, 0);
        assert_eq!(summary.errors, 0);
        assert!(
            cr_rows_for(&pool, art).await.is_empty(),
            "the source edge is released, so the refcount falls"
        );
        assert!(
            !storage.exists(&put.hash).await.unwrap(),
            "the last reference is gone, so the bytes are collected"
        );
        let purged: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM events WHERE stream_id = $1 AND event_type = 'ArtifactPurged'",
        )
        .bind(StreamId::artifact(art).to_string())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(purged, 1, "the terminal event closes the work item");
        let after: DateTime<Utc> =
            sqlx::query_scalar("SELECT deleted_at FROM artifacts WHERE id = $1")
                .bind(art)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            after, deleted_at,
            "the delete's timestamp is the audit fact"
        );
        assert!(
            !adapter
                .list_pending_purge(1000, None)
                .await
                .unwrap()
                .iter()
                .any(|p| p.artifact_id == art),
            "the work item does not come back"
        );

        cleanup(&pool, repo).await;
    }

    /// CAS bytes are shared: deleting one artifact over a content another
    /// artifact still holds removes only that artifact's reference. ADR
    /// 0054 — rows are not bytes.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn a_soft_delete_over_shared_bytes_leaves_the_blob_standing() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        let storage = Arc::new(hort_adapters_storage::FilesystemStorage::new(
            tmp.path().to_path_buf(),
        ));
        let put = storage
            .put(Box::new(std::io::Cursor::new(b"hello world".to_vec())))
            .await
            .unwrap();

        let repo = seed_repo(&pool).await;
        let doomed = seed_artifact(&pool, repo, "doomed", HASH_B, Some("released")).await;
        let keeper = seed_artifact(&pool, repo, "keeper", HASH_B, Some("released")).await;
        for art in [doomed, keeper] {
            sqlx::query("DELETE FROM content_references WHERE source_artifact_id = $1")
                .bind(art)
                .execute(&pool)
                .await
                .unwrap();
            insert_cr(&pool, repo, art, "primary_content", HASH_B).await;
        }

        let adapter = Arc::new(adapter(&pool).await);
        soft_delete(&pool, &adapter, doomed).await;

        let uc = PurgeUseCase::new(adapter.clone(), storage.clone(), Arc::new(ConvergedGate));
        let summary = uc.process_expired(Utc::now()).await.expect("sweep runs");

        assert_eq!(summary.blobs_kept, 1);
        assert_eq!(summary.blobs_deleted, 0);
        assert!(
            storage.exists(&put.hash).await.unwrap(),
            "another artifact still references these bytes"
        );
        assert!(cr_rows_for(&pool, doomed).await.is_empty());
        assert_eq!(
            cr_rows_for(&pool, keeper).await,
            vec![("primary_content".into(), HASH_B.into())],
            "the surviving artifact keeps its own edge"
        );
        let keeper_deleted_at: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT deleted_at FROM artifacts WHERE id = $1")
                .bind(keeper)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(keeper_deleted_at.is_none(), "the sibling stays live");
        let mut reader = storage.get(&put.hash).await.unwrap();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"hello world");

        cleanup(&pool, repo).await;
    }

    /// The shape the OCI manifest DELETE produces: the handler drops the
    /// manifest's keepalive edges before the soft delete, so the sweep's
    /// `DELETE … RETURNING` finds nothing and recovers the manifest's own
    /// targets from `artifacts.checksum_sha256` +
    /// `artifact_metadata.metadata_blob`. Its bytes must still be
    /// collected — that is the path every user delete reaches today.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn a_delete_whose_edges_were_already_swept_still_releases_its_bytes() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        let storage = Arc::new(hort_adapters_storage::FilesystemStorage::new(
            tmp.path().to_path_buf(),
        ));
        let manifest = storage
            .put(Box::new(std::io::Cursor::new(b"hello world".to_vec())))
            .await
            .unwrap();
        let meta = storage
            .put(Box::new(std::io::Cursor::new(b"foo".to_vec())))
            .await
            .unwrap();
        assert_eq!(meta.hash.as_ref(), HASH_C);

        let repo = seed_repo(&pool).await;
        let art = seed_artifact(&pool, repo, "manifest", HASH_B, Some("released")).await;
        seed_metadata_blob(&pool, art, HASH_C).await;
        // The handler's pre-delete sweep: every kind, including the
        // primary-content edge.
        sqlx::query("DELETE FROM content_references WHERE source_artifact_id = $1")
            .bind(art)
            .execute(&pool)
            .await
            .unwrap();

        let adapter = Arc::new(adapter(&pool).await);
        soft_delete(&pool, &adapter, art).await;

        let uc = PurgeUseCase::new(adapter.clone(), storage.clone(), Arc::new(ConvergedGate));
        let summary = uc.process_expired(Utc::now()).await.expect("sweep runs");

        assert_eq!(summary.user_deletes_visited, 1);
        assert_eq!(summary.blobs_deleted, 2, "manifest bytes and metadata blob");
        assert!(!storage.exists(&manifest.hash).await.unwrap());
        assert!(!storage.exists(&meta.hash).await.unwrap());

        cleanup(&pool, repo).await;
    }

    /// A mutable ref left pointing at a deleted artifact's hash does not
    /// hold its bytes. The `KeepLastN` tag exemption is scoped to that
    /// predicate; a delete is the caller's explicit instruction, and the
    /// row the ref names is one no read path resolves.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn a_tag_left_on_a_deleted_artifact_does_not_exempt_it() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        let storage = Arc::new(hort_adapters_storage::FilesystemStorage::new(
            tmp.path().to_path_buf(),
        ));
        let put = storage
            .put(Box::new(std::io::Cursor::new(b"hello world".to_vec())))
            .await
            .unwrap();

        let repo = seed_repo(&pool).await;
        let art = seed_artifact(&pool, repo, "tagged", HASH_B, Some("released")).await;
        sqlx::query("DELETE FROM content_references WHERE source_artifact_id = $1")
            .bind(art)
            .execute(&pool)
            .await
            .unwrap();
        insert_cr(&pool, repo, art, "primary_content", HASH_B).await;
        seed_mutable_ref(&pool, repo, "tagged", "latest", "hash", Some(HASH_B), None).await;

        let adapter = Arc::new(adapter(&pool).await);
        soft_delete(&pool, &adapter, art).await;
        let row = pending_for(&pool, art).await;
        assert!(row.tag_targeted, "the ref still resolves to the hash");
        assert!(row.user_deleted);

        let uc = PurgeUseCase::new(adapter.clone(), storage.clone(), Arc::new(ConvergedGate));
        let summary = uc.process_expired(Utc::now()).await.expect("sweep runs");

        assert_eq!(summary.skipped_tag_exempt, 0);
        assert_eq!(summary.blobs_deleted, 1);
        assert!(!storage.exists(&put.hash).await.unwrap());

        cleanup(&pool, repo).await;
    }

    /// Recovery after a delete-driven collection. The trap this walks:
    /// if any dedup or blob-existence lookup could still see the retired
    /// row, a re-push would skip the CAS write and leave a row whose
    /// bytes are gone — a permanent 404 that looks healthy in the
    /// database. Both lookups the ingest path uses to short-circuit a
    /// write (`find_by_path` for the path dedup, `find_by_checksum` for
    /// the by-hash guard) filter `deleted_at IS NULL`, and the purge
    /// always leaves `deleted_at` set, so the write always happens.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn delete_then_purge_then_repush_serves_the_bytes_again() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        let storage = Arc::new(hort_adapters_storage::FilesystemStorage::new(
            tmp.path().to_path_buf(),
        ));
        let bytes = b"hello world".to_vec();
        let first = storage
            .put(Box::new(std::io::Cursor::new(bytes.clone())))
            .await
            .unwrap();

        let repo = seed_repo(&pool).await;
        let old = seed_artifact(&pool, repo, "repush", HASH_B, Some("released")).await;
        let path: String = sqlx::query_scalar("SELECT path FROM artifacts WHERE id = $1")
            .bind(old)
            .fetch_one(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM content_references WHERE source_artifact_id = $1")
            .bind(old)
            .execute(&pool)
            .await
            .unwrap();
        insert_cr(&pool, repo, old, "primary_content", HASH_B).await;

        let adapter = Arc::new(adapter(&pool).await);
        soft_delete(&pool, &adapter, old).await;
        let uc = PurgeUseCase::new(adapter.clone(), storage.clone(), Arc::new(ConvergedGate));
        assert_eq!(
            uc.process_expired(Utc::now())
                .await
                .expect("sweep runs")
                .blobs_deleted,
            1
        );
        assert!(!storage.exists(&first.hash).await.unwrap());

        // Neither ingest short-circuit can see the retired row, so the
        // re-push cannot skip the blob write.
        let artifact_repo = crate::artifact_repo::PgArtifactRepository::new(
            pool.clone(),
            adapter.event_store.clone(),
        );
        assert!(artifact_repo
            .find_by_path(repo, &path)
            .await
            .unwrap()
            .is_none());
        assert!(artifact_repo
            .find_by_checksum(&first.hash)
            .await
            .unwrap()
            .is_none());

        let second = storage
            .put(Box::new(std::io::Cursor::new(bytes.clone())))
            .await
            .unwrap();
        assert_eq!(second.hash, first.hash, "content addressing is stable");
        let fresh = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO artifacts (
                id, repository_id, name, name_as_published, version, path,
                size_bytes, checksum_sha256, content_type, storage_key,
                quarantine_status
            ) VALUES (
                $1, $2, 'repush', 'repush', '1.0.0', $3,
                $4, $5, 'application/octet-stream', $3, 'released'
            )
            "#,
        )
        .bind(fresh)
        .bind(repo)
        .bind(&path)
        .bind(i64::try_from(bytes.len()).unwrap())
        .bind(second.hash.as_ref())
        .execute(&pool)
        .await
        .unwrap();

        let live = artifact_repo
            .find_by_path(repo, &path)
            .await
            .unwrap()
            .expect("the re-pushed path is live again");
        assert_eq!(live.id, fresh);
        assert_ne!(fresh, old);
        let mut reader = storage.get(&second.hash).await.unwrap();
        let mut fetched = Vec::new();
        reader.read_to_end(&mut fetched).await.unwrap();
        assert_eq!(fetched, bytes, "the artifact serves its bytes again");

        cleanup(&pool, repo).await;
    }

    // -----------------------------------------------------------------
    // The blob-reclamation lock: the purge locks the artifact, but the
    // blob is what it destroys
    // -----------------------------------------------------------------

    /// Seed one repository holding one artifact whose primary content
    /// is `hash`, with the durable purge worklist already prepared and
    /// its refcount recorded as zero. This is the exact state the race
    /// is about: the count has been taken, the bytes are still there,
    /// and the delete has not happened yet.
    async fn worklist_prepared_at_zero(
        pool: &PgPool,
        adapter: &PgPurgeGcPort,
        hash: &str,
    ) -> (Uuid, Uuid) {
        let repo = seed_repo(pool).await;
        let art = seed_artifact(pool, repo, "reclaim-race", hash, Some("released")).await;
        sqlx::query("DELETE FROM content_references WHERE source_artifact_id = $1")
            .bind(art)
            .execute(pool)
            .await
            .unwrap();
        insert_cr(pool, repo, art, "primary_content", hash).await;
        append_event(pool, art, "ArtifactExpired", 0).await;

        let refs = adapter
            .purge_artifact_refs(art, Utc::now())
            .await
            .expect("worklist prepared");
        let refs = prepared(refs);
        assert_eq!(refs.len(), 1);
        assert_eq!(
            refs[0].refs_remaining, 0,
            "the preparation transaction saw no remaining references"
        );
        (repo, art)
    }

    /// Record a `primary_content` reference through the **real** ingest
    /// write path (`ContentReferenceIndex::insert`) — the path a
    /// deduplicating ingest takes when `exists(hash)` is true, so
    /// nothing is written to CAS and only the reference is recorded.
    async fn ingest_dedup_reference(pool: &PgPool, repo: Uuid, source: Uuid, hash: &ContentHash) {
        use hort_domain::ports::content_reference_index::{
            ContentReference, ContentReferenceIndex,
        };
        crate::pg_content_reference_repo::PgContentReferenceRepo::new(pool.clone())
            .insert(ContentReference {
                source_artifact_id: source,
                target_content_hash: hash.clone(),
                kind: "primary_content".to_owned(),
                metadata: serde_json::Value::Object(serde_json::Map::new()),
                repository_id: repo,
                recorded_at: Utc::now(),
            })
            .await
            .expect("reference recorded");
    }

    /// **The race.** The sweep has a worklist row saying "zero
    /// references"; before it reaches the bytes, an ingest deduplicates
    /// onto the same hash — `exists(hash)` is true, so nothing is
    /// written — and records its reference. The worklist's zero is now
    /// stale.
    ///
    /// Before the fix, `finish_one_ref` read that stale zero and
    /// deleted: the new artifact ended up pointing at bytes that no
    /// longer existed. Now the count is re-read under the hash lock
    /// immediately before the delete, sees the new reference, and keeps
    /// the blob — and the `ArtifactPurged` it emits carries the count
    /// that actually held rather than the zero that did not.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn a_dedup_landing_between_the_count_and_the_delete_keeps_its_bytes() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        let storage = Arc::new(hort_adapters_storage::FilesystemStorage::new(
            tmp.path().to_path_buf(),
        ));
        let put = storage
            .put(Box::new(std::io::Cursor::new(b"hello world".to_vec())))
            .await
            .unwrap();
        assert_eq!(put.hash.as_ref(), HASH_B);

        let adapter = Arc::new(adapter(&pool).await);
        let (repo, expiring) = worklist_prepared_at_zero(&pool, &adapter, HASH_B).await;

        // The concurrent ingest: a second artifact deduplicates onto the
        // same content and records its reference.
        let newcomer = seed_artifact(&pool, repo, "dedup-newcomer", HASH_B, Some("released")).await;
        sqlx::query("DELETE FROM content_references WHERE source_artifact_id = $1")
            .bind(newcomer)
            .execute(&pool)
            .await
            .unwrap();
        ingest_dedup_reference(&pool, repo, newcomer, &put.hash).await;

        let uc = PurgeUseCase::new(adapter.clone(), storage.clone(), Arc::new(ConvergedGate));
        let summary = uc.process_expired(Utc::now()).await.expect("sweep runs");

        assert!(
            storage.exists(&put.hash).await.unwrap(),
            "the newcomer's bytes must survive the sweep that decided \
             before it arrived"
        );
        assert_eq!(summary.blobs_deleted, 0);
        assert_eq!(summary.blobs_kept, 1);
        assert_eq!(summary.errors, 0);

        // The expiring artifact still finishes — declining to delete is
        // not declining to complete.
        let purged: Vec<i64> = sqlx::query_scalar(
            "SELECT (event_data->'data'->>'refs_remaining')::bigint FROM events \
             WHERE stream_id = $1 AND event_type = 'ArtifactPurged'",
        )
        .bind(StreamId::artifact(expiring).to_string())
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(
            purged,
            vec![1],
            "the terminal event states the count observed under the lock"
        );

        cleanup(&pool, repo).await;
    }

    /// The other half of the same window: the ingest's reference write
    /// is **in flight** — it holds the hash lock and has not committed,
    /// so the sweep's re-count could not see it even if it ran. The
    /// sweep does not run it: the lock is taken with `try`, contention
    /// is an answer, and the answer is "not this run".
    ///
    /// Then the reference commits and the sweep asks again, which is
    /// the retry half of skip-when-in-doubt: a deferred blob is not a
    /// lost one, and the worklist row is what carries it forward.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn an_in_flight_reference_write_defers_the_sweep_which_then_retries() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        let storage = Arc::new(hort_adapters_storage::FilesystemStorage::new(
            tmp.path().to_path_buf(),
        ));
        let put = storage
            .put(Box::new(std::io::Cursor::new(b"hello world".to_vec())))
            .await
            .unwrap();

        let adapter = Arc::new(adapter(&pool).await);
        let (repo, art) = worklist_prepared_at_zero(&pool, &adapter, HASH_B).await;
        let uc = PurgeUseCase::new(adapter.clone(), storage.clone(), Arc::new(ConvergedGate));

        // An uncommitted reference write, modelled exactly as
        // `PgContentReferenceRepo::insert` opens one: a transaction that
        // has taken the hash lock and not yet committed.
        let mut in_flight = pool.begin().await.unwrap();
        crate::blob_lock::lock_blob_in_tx(&mut in_flight, &put.hash)
            .await
            .unwrap();

        let deferred = uc.process_expired(Utc::now()).await.expect("sweep runs");
        assert_eq!(deferred.blobs_deferred, 1);
        assert_eq!(deferred.blobs_deleted, 0);
        assert_eq!(deferred.purged_events, 0);
        assert_eq!(
            deferred.errors, 0,
            "a deferral is the mechanism working, not an error"
        );
        assert!(
            storage.exists(&put.hash).await.unwrap(),
            "nothing may be deleted while a reference write is in flight"
        );

        // The skip is observable in the durable state too: the worklist
        // row is still there, uncompleted, which is what makes the next
        // run pick it up.
        let outstanding: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM artifact_purge_worklist \
             WHERE artifact_id = $1 AND completed_at IS NULL",
        )
        .bind(art)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(outstanding, 1);

        // The reference write finishes (rolled back here — the point is
        // that the lock frees), and the next run reclaims.
        in_flight.rollback().await.unwrap();
        let second = uc.process_expired(Utc::now()).await.expect("sweep runs");
        assert_eq!(second.blobs_deferred, 0);
        assert_eq!(second.blobs_deleted, 1);
        assert_eq!(second.purged_events, 1);
        assert!(
            !storage.exists(&put.hash).await.unwrap(),
            "with the lock free and the count still zero, the bytes go"
        );

        cleanup(&pool, repo).await;
    }

    /// **Both sides take the same lock — shown, not asserted.** The
    /// sweep holds a granted reclamation lease; the real ingest write
    /// path (`ContentReferenceIndex::insert`) is started against the
    /// same hash and does not complete while the lease is held. Release
    /// the lease and it completes.
    ///
    /// A lock only the deleting side takes would leave this insert
    /// finishing immediately, which is exactly what the `timeout`
    /// asserts it does not do. The second half — a *different* hash
    /// inserting straight through the same held lease — is what keeps
    /// the first half from being satisfied by any global lock.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial(hort_pg_db)]
    async fn the_ingest_write_waits_on_the_very_lock_the_sweep_holds() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let adapter = adapter(&pool).await;
        let (repo, art) = worklist_prepared_at_zero(&pool, &adapter, HASH_B).await;
        let target: ContentHash = HASH_B.parse().unwrap();
        let other: ContentHash = HASH_C.parse().unwrap();

        let newcomer = seed_artifact(&pool, repo, "waiting-ingest", HASH_B, Some("released")).await;
        sqlx::query("DELETE FROM content_references WHERE source_artifact_id = $1")
            .bind(newcomer)
            .execute(&pool)
            .await
            .unwrap();

        let BlobReclaim::Granted(guard) = adapter
            .begin_blob_reclaim(art, &target)
            .await
            .expect("lease")
        else {
            panic!("an unreferenced hash on a free lock must grant");
        };

        let landed = Arc::new(AtomicBool::new(false));
        let waiting = {
            let pool = pool.clone();
            let target = target.clone();
            let landed = Arc::clone(&landed);
            tokio::spawn(async move {
                ingest_dedup_reference(&pool, repo, newcomer, &target).await;
                landed.store(true, Ordering::SeqCst);
            })
        };

        // A reference write on a *different* hash is unaffected: the
        // lock is per-blob, not a global reclamation mutex. This also
        // gives the spawned write above a real, timed opportunity to
        // finish — an assertion that only ever observed an unscheduled
        // task would pass with no lock at all.
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            ingest_dedup_reference(&pool, repo, newcomer, &other),
        )
        .await
        .expect("an unrelated hash must not queue behind this lease");
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        assert!(
            !landed.load(Ordering::SeqCst),
            "the ingest write must be blocked on the lease's lock"
        );

        guard.release().await.expect("release");
        tokio::time::timeout(std::time::Duration::from_secs(10), waiting)
            .await
            .expect("the ingest write proceeds once the lease ends")
            .expect("the spawned write did not panic");

        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM content_references WHERE target_content_hash = $1",
        )
        .bind(HASH_B)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count, 1, "the newcomer's reference landed after the lease");

        cleanup(&pool, repo).await;
    }

    /// The refcount-reconcile repair is a reference write too — it
    /// restores a claim on bytes that already exist — so it takes the
    /// same lock. Same proof shape as the ingest path: it does not
    /// complete while a reclamation lease is held on its target.
    ///
    /// Reconcile and purge are ordered by a convergence gate, not kept
    /// apart by it: the gate says a sweep has converged *once*, not
    /// that one is not running now.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[serial(hort_pg_db)]
    async fn the_reconcile_repair_waits_on_the_same_lock() {
        use hort_domain::ports::refcount_reconcile::RefcountRepair;

        let Some(pool) = maybe_pool().await else {
            return;
        };
        let adapter = adapter(&pool).await;
        let (repo, art) = worklist_prepared_at_zero(&pool, &adapter, HASH_B).await;
        let target: ContentHash = HASH_B.parse().unwrap();

        let drifted = seed_artifact(&pool, repo, "drifted", HASH_B, Some("released")).await;
        sqlx::query("DELETE FROM content_references WHERE source_artifact_id = $1")
            .bind(drifted)
            .execute(&pool)
            .await
            .unwrap();

        let BlobReclaim::Granted(guard) = adapter
            .begin_blob_reclaim(art, &target)
            .await
            .expect("lease")
        else {
            panic!("an unreferenced hash on a free lock must grant");
        };

        let landed = Arc::new(AtomicBool::new(false));
        let repairing = {
            let pool = pool.clone();
            let target = target.clone();
            let landed = Arc::clone(&landed);
            tokio::spawn(async move {
                crate::refcount_reconcile::PgRefcountReconcile::new(pool)
                    .apply_repair(
                        repo,
                        &RefcountRepair::CreatePrimaryContent {
                            source_artifact_id: drifted,
                            expected_hash: target,
                        },
                    )
                    .await
                    .expect("repair applied");
                landed.store(true, Ordering::SeqCst);
            })
        };

        // Give the spawned repair a real chance to run to completion if
        // it were not blocked: an assertion that only ever observed an
        // unscheduled task would pass with no lock at all.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert!(
            !landed.load(Ordering::SeqCst),
            "the reconcile repair must be blocked on the lease's lock"
        );

        guard.release().await.expect("release");
        tokio::time::timeout(std::time::Duration::from_secs(10), repairing)
            .await
            .expect("the repair proceeds once the lease ends")
            .expect("the spawned repair did not panic");

        cleanup(&pool, repo).await;
    }

    // -----------------------------------------------------------------
    // GC-protected evidence claims its bytes — with no reference edge
    // to claim them with
    // -----------------------------------------------------------------

    /// Seed one GC-protected artifact in `repo` whose **primary
    /// content** is `hash`, and assert the structural precondition this
    /// whole hazard rests on: it holds **no** `content_references` row,
    /// so no refcount can see its claim. `refcount_reconcile` is what
    /// keeps it that way (it mints no edge for a protected artifact),
    /// and that exclusion is deliberate — so the predicate under test
    /// cannot be replaced by "mint the edge after all".
    async fn seed_protected_primary_claimant(
        pool: &PgPool,
        repo: Uuid,
        name: &str,
        hash: &str,
        status: &str,
    ) -> Uuid {
        let art = seed_artifact(pool, repo, name, hash, Some(status)).await;
        sqlx::query("DELETE FROM content_references WHERE source_artifact_id = $1")
            .bind(art)
            .execute(pool)
            .await
            .unwrap();
        assert_eq!(
            cr_rows_for(pool, art).await,
            Vec::<(String, String)>::new(),
            "a protected claimant holds no reference edge — that is the \
             premise, not an accident of this fixture"
        );
        art
    }

    /// Read the `refs_remaining` of every `ArtifactPurged` on an
    /// artifact's stream.
    async fn purged_refs_remaining(pool: &PgPool, artifact: Uuid) -> Vec<i64> {
        sqlx::query_scalar(
            "SELECT (event_data->'data'->>'refs_remaining')::bigint FROM events \
             WHERE stream_id = $1 AND event_type = 'ArtifactPurged'",
        )
        .bind(StreamId::artifact(artifact).to_string())
        .fetch_all(pool)
        .await
        .unwrap()
    }

    /// **The finding.** A quarantined / rejected / scan-indeterminate
    /// artifact shares its content hash with a released sibling. The
    /// sibling expires and is purged; the protected artifact was never
    /// a purge candidate and never acquired an `ArtifactExpired`.
    ///
    /// Both of those protections are about the *artifact*. Reclamation
    /// is about the *bytes*, which CAS shares — and the protected
    /// artifact contributes **zero** to the refcount of its own hash,
    /// because the refcount repair deliberately mints no edge for
    /// retained evidence. So the sibling's purge read `0` under the
    /// lock and deleted the evidence's bytes with nothing anywhere
    /// having made a wrong decision.
    ///
    /// Now the zero is not the whole answer: the bytes stay, the
    /// sibling's purge still completes, and its `ArtifactPurged`
    /// carries the claim count so "the blob stays" is readable from the
    /// stream rather than contradicted by it.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn a_protected_sibling_keeps_the_shared_primary_content_bytes() {
        let Some(pool) = maybe_pool().await else {
            return;
        };

        for status in ["quarantined", "rejected", "scan_indeterminate"] {
            let tmp = tempfile::tempdir().unwrap();
            let storage = Arc::new(hort_adapters_storage::FilesystemStorage::new(
                tmp.path().to_path_buf(),
            ));
            let put = storage
                .put(Box::new(std::io::Cursor::new(b"hello world".to_vec())))
                .await
                .unwrap();
            assert_eq!(put.hash.as_ref(), HASH_B);

            let adapter = Arc::new(adapter(&pool).await);
            let (repo, expiring) = worklist_prepared_at_zero(&pool, &adapter, HASH_B).await;
            let evidence =
                seed_protected_primary_claimant(&pool, repo, "evidence", HASH_B, status).await;

            // The protected artifact really is invisible to the
            // refcount: this is the count the lease re-reads, and it is
            // zero with the evidence row sitting right there.
            let refs: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM content_references WHERE target_content_hash = $1",
            )
            .bind(HASH_B)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(refs, 0, "{status}: the refcount cannot see the claim");

            let uc = PurgeUseCase::new(adapter.clone(), storage.clone(), Arc::new(ConvergedGate));
            let summary = uc.process_expired(Utc::now()).await.expect("sweep runs");

            assert!(
                storage.exists(&put.hash).await.unwrap(),
                "{status}: the evidence's bytes must survive its sibling's purge"
            );
            assert_eq!(summary.blobs_deleted, 0, "{status}");
            assert_eq!(summary.blobs_kept, 1, "{status}");
            assert_eq!(
                summary.blobs_deferred, 0,
                "{status}: a protected claim is terminal, not a deferral — a \
                 rejected artifact is permanent and re-asking would never \
                 finish the sibling's purge"
            );
            assert_eq!(summary.errors, 0, "{status}");
            assert_eq!(
                purged_refs_remaining(&pool, expiring).await,
                vec![1],
                "{status}: the terminal event states the claim that held, so \
                 `0 ⇒ deleted` still reads true"
            );

            // The evidence itself is untouched: still live, still
            // protected, still not a purge candidate.
            let still_there: Option<Option<DateTime<Utc>>> =
                sqlx::query_scalar("SELECT deleted_at FROM artifacts WHERE id = $1")
                    .bind(evidence)
                    .fetch_optional(&pool)
                    .await
                    .unwrap();
            assert_eq!(
                still_there,
                Some(None),
                "{status}: the evidence row is untouched by its sibling's purge"
            );

            cleanup(&pool, repo).await;
        }
    }

    /// **The other half of the same claim, and the easy one to miss.**
    /// A protected artifact claims *two* hashes: its primary content
    /// (`artifacts.checksum_sha256`) and its metadata blob
    /// (`artifact_metadata.metadata_blob`) — a different table. Here
    /// the protected artifact's primary content is a *different* hash
    /// entirely, so a predicate that asked only `artifacts` would see
    /// no claimant and delete the evidence's metadata bytes.
    ///
    /// Deliberately its own test rather than a second status on the
    /// one above: the two claims come from two tables, and a single
    /// test that happened to satisfy both with the same hash would go
    /// green with half the predicate missing.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn a_protected_metadata_blob_keeps_the_shared_bytes_too() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        let storage = Arc::new(hort_adapters_storage::FilesystemStorage::new(
            tmp.path().to_path_buf(),
        ));
        let put = storage
            .put(Box::new(std::io::Cursor::new(b"hello world".to_vec())))
            .await
            .unwrap();
        assert_eq!(put.hash.as_ref(), HASH_B);

        let adapter = Arc::new(adapter(&pool).await);
        let (repo, expiring) = worklist_prepared_at_zero(&pool, &adapter, HASH_B).await;

        // The evidence's own content is HASH_C; only its metadata blob
        // is the hash under reclamation. Nothing in `artifacts` names
        // HASH_B for this artifact.
        let evidence =
            seed_protected_primary_claimant(&pool, repo, "meta-evidence", HASH_C, "quarantined")
                .await;
        seed_metadata_blob(&pool, evidence, HASH_B).await;
        let primary_claim: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM artifacts WHERE trim(checksum_sha256) = $1 \
             AND quarantine_status = 'quarantined'",
        )
        .bind(HASH_B)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            primary_claim, 0,
            "the claim must come from artifact_metadata alone, or this test \
             would pass with the metadata branch missing"
        );

        let uc = PurgeUseCase::new(adapter.clone(), storage.clone(), Arc::new(ConvergedGate));
        let summary = uc.process_expired(Utc::now()).await.expect("sweep runs");

        assert!(
            storage.exists(&put.hash).await.unwrap(),
            "the bytes a protected artifact's metadata blob names must survive"
        );
        assert_eq!(summary.blobs_deleted, 0);
        assert_eq!(summary.blobs_kept, 1);
        assert_eq!(summary.errors, 0);
        assert_eq!(purged_refs_remaining(&pool, expiring).await, vec![1]);

        cleanup(&pool, repo).await;
    }

    /// The counter-assertion that keeps the two tests above from being
    /// satisfied by a predicate that simply never grants: with no
    /// protected claimant and no reference row the bytes still go, and
    /// the terminal event still says `refs_remaining = 0`.
    ///
    /// The two near-misses are what make this worth its own test: a
    /// claimant in a **non**-protected state (`released`) and a
    /// claimant that is **soft-deleted** both name the same hash here,
    /// and neither may keep the blob. The first would turn every
    /// deduplicated sibling into a permanent hold; the second would
    /// make a delete unreclaimable forever, since a soft-deleted row is
    /// retained for audit and never goes away.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn an_unprotected_or_deleted_claimant_does_not_keep_the_bytes() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let tmp = tempfile::tempdir().unwrap();
        let storage = Arc::new(hort_adapters_storage::FilesystemStorage::new(
            tmp.path().to_path_buf(),
        ));
        let put = storage
            .put(Box::new(std::io::Cursor::new(b"hello world".to_vec())))
            .await
            .unwrap();

        let adapter = Arc::new(adapter(&pool).await);
        let (repo, expiring) = worklist_prepared_at_zero(&pool, &adapter, HASH_B).await;

        // Edgeless, same hash, not protected.
        seed_protected_primary_claimant(&pool, repo, "released-twin", HASH_B, "released").await;
        // Edgeless, same hash, protected status — but soft-deleted, so
        // it is a retained audit row and not evidence anything may read.
        let gone =
            seed_protected_primary_claimant(&pool, repo, "retired-evidence", HASH_B, "rejected")
                .await;
        sqlx::query("UPDATE artifacts SET deleted_at = now() WHERE id = $1")
            .bind(gone)
            .execute(&pool)
            .await
            .unwrap();

        let uc = PurgeUseCase::new(adapter.clone(), storage.clone(), Arc::new(ConvergedGate));
        let summary = uc.process_expired(Utc::now()).await.expect("sweep runs");

        assert!(
            !storage.exists(&put.hash).await.unwrap(),
            "with nothing protected claiming the hash, the bytes go"
        );
        assert_eq!(summary.blobs_deleted, 1);
        assert_eq!(summary.blobs_kept, 0);
        assert_eq!(summary.errors, 0);
        assert_eq!(
            purged_refs_remaining(&pool, expiring).await,
            vec![0],
            "`0` still means the blob was deleted"
        );

        cleanup(&pool, repo).await;
    }

    /// The lease's answer, read straight off the adapter rather than
    /// through a whole sweep: `ProtectedClaim`, carrying the number of
    /// claimants, with the durable worklist row corrected in place so a
    /// retry and the terminal event agree with it.
    ///
    /// Also pins the counting rule: one artifact claiming the hash
    /// twice — as its primary content *and* as its metadata blob — is
    /// **one** claimant, because the number is a count of artifacts
    /// holding the bytes.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn the_lease_reports_protected_claims_and_counts_claimants_once() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let adapter = adapter(&pool).await;
        let (repo, art) = worklist_prepared_at_zero(&pool, &adapter, HASH_B).await;
        let target: ContentHash = HASH_B.parse().unwrap();

        // One claimant, claiming through both columns at once.
        let both =
            seed_protected_primary_claimant(&pool, repo, "both-columns", HASH_B, "quarantined")
                .await;
        seed_metadata_blob(&pool, both, HASH_B).await;

        assert!(
            matches!(
                adapter
                    .begin_blob_reclaim(art, &target)
                    .await
                    .expect("lease"),
                BlobReclaim::ProtectedClaim { claimants: 1 }
            ),
            "an artifact claiming the hash through both columns is one \
             claimant, not two"
        );
        let persisted: i64 = sqlx::query_scalar(
            "SELECT refs_remaining FROM artifact_purge_worklist \
             WHERE artifact_id = $1 AND content_hash = $2",
        )
        .bind(art)
        .bind(HASH_B)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            persisted, 1,
            "the worklist's zero is corrected to the claim count, exactly as \
             the Referenced path corrects it — the terminal batch is \
             validated against this row"
        );

        // A second, distinct claimant is a second claim.
        seed_protected_primary_claimant(&pool, repo, "second-evidence", HASH_B, "rejected").await;
        assert!(matches!(
            adapter
                .begin_blob_reclaim(art, &target)
                .await
                .expect("lease"),
            BlobReclaim::ProtectedClaim { claimants: 2 }
        ));

        cleanup(&pool, repo).await;
    }

    /// A reference row and a protected claimant at the same time: the
    /// refcount answers first and the protected-claim query never runs.
    /// That ordering is the point — a non-zero refcount already keeps
    /// the blob, so the second question has nothing left to decide, and
    /// asking it anyway would put a second query on every kept blob.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn a_live_reference_answers_before_the_protected_claim_query() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let adapter = adapter(&pool).await;
        let (repo, art) = worklist_prepared_at_zero(&pool, &adapter, HASH_B).await;
        let target: ContentHash = HASH_B.parse().unwrap();

        let newcomer = seed_artifact(&pool, repo, "live-ref", HASH_B, Some("released")).await;
        sqlx::query("DELETE FROM content_references WHERE source_artifact_id = $1")
            .bind(newcomer)
            .execute(&pool)
            .await
            .unwrap();
        ingest_dedup_reference(&pool, repo, newcomer, &target).await;
        seed_protected_primary_claimant(&pool, repo, "also-evidence", HASH_B, "quarantined").await;

        assert!(
            matches!(
                adapter
                    .begin_blob_reclaim(art, &target)
                    .await
                    .expect("lease"),
                BlobReclaim::Referenced { refs_now: 1 }
            ),
            "a live reference row is reported as `Referenced` — the variant \
             whose value is defined as a `content_references` count"
        );

        cleanup(&pool, repo).await;
    }

    /// Three of the lease's four answers, straight from the adapter:
    /// granted on a free lock over an unclaimed hash, `Referenced`
    /// (with the worklist row corrected in place) once a reference
    /// exists, and `Contended` while someone else holds the lock. The
    /// fourth, `ProtectedClaim`, has its own tests above — it is
    /// reached only when the refcount is zero, so it cannot be
    /// scripted into this sequence.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn the_lease_reports_granted_referenced_and_contended() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let adapter = adapter(&pool).await;
        let (repo, art) = worklist_prepared_at_zero(&pool, &adapter, HASH_B).await;
        let target: ContentHash = HASH_B.parse().unwrap();

        // Granted, and released cleanly.
        let BlobReclaim::Granted(guard) = adapter
            .begin_blob_reclaim(art, &target)
            .await
            .expect("lease")
        else {
            panic!("expected Granted");
        };

        // Contended: the lease above still holds the lock.
        assert!(
            matches!(
                adapter
                    .begin_blob_reclaim(art, &target)
                    .await
                    .expect("lease"),
                BlobReclaim::Contended
            ),
            "a second lease on a held lock is contention, not a wait"
        );
        guard.release().await.expect("release");

        // Referenced: a reference arrives, and the lease reports the
        // live count *and* corrects the durable worklist row, so the
        // terminal event and a later retry both read the truth.
        let newcomer = seed_artifact(&pool, repo, "later-claim", HASH_B, Some("released")).await;
        sqlx::query("DELETE FROM content_references WHERE source_artifact_id = $1")
            .bind(newcomer)
            .execute(&pool)
            .await
            .unwrap();
        ingest_dedup_reference(&pool, repo, newcomer, &target).await;

        assert!(matches!(
            adapter
                .begin_blob_reclaim(art, &target)
                .await
                .expect("lease"),
            BlobReclaim::Referenced { refs_now: 1 }
        ));
        let persisted: i64 = sqlx::query_scalar(
            "SELECT refs_remaining FROM artifact_purge_worklist \
             WHERE artifact_id = $1 AND content_hash = $2",
        )
        .bind(art)
        .bind(HASH_B)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            persisted, 1,
            "the worklist's stale zero is corrected under the lock"
        );

        cleanup(&pool, repo).await;
    }

    /// A *referenced* hash with no worklist row to correct is a bug in
    /// the caller, not a silent no-op: the refresh has nowhere to land,
    /// and a sweep that carried on would emit a terminal event stating
    /// a count no durable row holds.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn a_referenced_lease_with_no_worklist_row_is_loud() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let adapter = adapter(&pool).await;
        let repo = seed_repo(&pool).await;
        let art = seed_artifact(&pool, repo, "no-worklist", HASH_B, Some("released")).await;
        sqlx::query("DELETE FROM content_references WHERE source_artifact_id = $1")
            .bind(art)
            .execute(&pool)
            .await
            .unwrap();
        insert_cr(&pool, repo, art, "primary_content", HASH_B).await;
        let target: ContentHash = HASH_B.parse().unwrap();

        let err = adapter
            .begin_blob_reclaim(art, &target)
            .await
            .expect_err("a referenced hash with no worklist row must not pass silently");
        assert!(matches!(err, DomainError::Invariant(_)));
        assert!(err.to_string().contains("no worklist row"));

        cleanup(&pool, repo).await;
    }

    /// The pending-purge query is keyset-paged: a page is bounded by
    /// `limit` and starts strictly after `after_artifact_id`, which is
    /// what lets the sweep cap a first run that would otherwise have to
    /// load the whole backlog to find out how big it was.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn the_pending_query_pages_by_keyset_and_respects_the_limit() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let adapter = adapter(&pool).await;

        let mut seeded = Vec::new();
        for i in 0..3 {
            let art =
                seed_artifact(&pool, repo, &format!("paged-{i}"), HASH_A, Some("released")).await;
            append_event(&pool, art, "ArtifactExpired", 0).await;
            seeded.push(art);
        }
        seeded.sort();

        let first = adapter.list_pending_purge(2, None).await.unwrap();
        let first_ids: Vec<Uuid> = first.iter().map(|p| p.artifact_id).collect();
        assert_eq!(first_ids, seeded[..2].to_vec(), "ordered, and capped at 2");

        let second = adapter
            .list_pending_purge(2, Some(seeded[1]))
            .await
            .unwrap();
        let second_ids: Vec<Uuid> = second.iter().map(|p| p.artifact_id).collect();
        assert_eq!(
            second_ids,
            seeded[2..].to_vec(),
            "the cursor is exclusive, so no row is seen twice"
        );

        assert!(
            adapter
                .list_pending_purge(2, Some(seeded[2]))
                .await
                .unwrap()
                .is_empty(),
            "past the last row the page is empty, which ends the walk"
        );

        cleanup(&pool, repo).await;
    }

    // -----------------------------------------------------------------
    // The page is a snapshot: the protection rules are re-read under
    // the artifact lock
    // -----------------------------------------------------------------

    /// What the mutation a window test injects does. Boxed and
    /// `FnOnce` so it can capture a pool and fire exactly once.
    type Mutation =
        Box<dyn FnOnce() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send>;

    /// A [`PurgeGcPort`] that runs one mutation the first time the
    /// sweep prepares an artifact — so the mutation lands **after** the
    /// page was read and **before** the next artifact's destructive
    /// step. That is the window under test, and it is the sweep's
    /// longest one: everything done to the items ahead of an artifact,
    /// storage deletes included, happens inside it.
    ///
    /// A decorator rather than a mutation performed inline before the
    /// call, because inline would prove only that the fresh read sees a
    /// value written before the sweep started. The point is that the
    /// page row the sweep is carrying says something else.
    struct MutateAfterFirstPrepare {
        inner: PgPurgeGcPort,
        mutation: Mutex<Option<Mutation>>,
    }

    impl MutateAfterFirstPrepare {
        fn new(inner: PgPurgeGcPort, mutation: Mutation) -> Self {
            Self {
                inner,
                mutation: Mutex::new(Some(mutation)),
            }
        }
    }

    impl PurgeGcPort for MutateAfterFirstPrepare {
        fn list_pending_purge(
            &self,
            limit: u32,
            after_artifact_id: Option<Uuid>,
        ) -> BoxFuture<'_, DomainResult<Vec<PendingPurge>>> {
            self.inner.list_pending_purge(limit, after_artifact_id)
        }

        fn purge_artifact_refs(
            &self,
            artifact_id: Uuid,
            retired_at: DateTime<Utc>,
        ) -> BoxFuture<'_, DomainResult<PurgePreparation>> {
            let fire = self.mutation.lock().unwrap().take();
            Box::pin(async move {
                if let Some(fire) = fire {
                    fire().await;
                }
                self.inner
                    .purge_artifact_refs(artifact_id, retired_at)
                    .await
            })
        }

        fn begin_blob_reclaim(
            &self,
            artifact_id: Uuid,
            content_hash: &ContentHash,
        ) -> BoxFuture<'_, DomainResult<BlobReclaim>> {
            self.inner.begin_blob_reclaim(artifact_id, content_hash)
        }

        fn mark_purge_ref_complete(
            &self,
            artifact_id: Uuid,
            content_hash: &ContentHash,
            completed_at: DateTime<Utc>,
        ) -> BoxFuture<'_, DomainResult<()>> {
            self.inner
                .mark_purge_ref_complete(artifact_id, content_hash, completed_at)
        }

        fn complete_artifact_purge(
            &self,
            artifact_id: Uuid,
            retired_at: DateTime<Utc>,
            events: AppendEvents,
        ) -> BoxFuture<'_, DomainResult<()>> {
            self.inner
                .complete_artifact_purge(artifact_id, retired_at, events)
        }
    }

    /// Two released artifacts, each with its own bytes in CAS, each
    /// with its own `primary_content` edge and a pending
    /// `ArtifactExpired` carrying `reason`. Returns
    /// `(repo, storage, tmp, leader, leader_hash, victim, victim_hash)`
    /// with `leader` the one the page serves first — so a mutation
    /// fired during the leader's preparation is inside the victim's
    /// window.
    async fn two_artifacts_one_window(
        pool: &PgPool,
        reason: serde_json::Value,
    ) -> (
        Uuid,
        Arc<hort_adapters_storage::FilesystemStorage>,
        tempfile::TempDir,
        Uuid,
        &'static str,
        Uuid,
        &'static str,
    ) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(hort_adapters_storage::FilesystemStorage::new(
            tmp.path().to_path_buf(),
        ));
        for (bytes, expected) in [(b"hello world".to_vec(), HASH_B), (b"foo".to_vec(), HASH_C)] {
            let put = storage
                .put(Box::new(std::io::Cursor::new(bytes)))
                .await
                .expect("seed CAS");
            assert_eq!(put.hash.as_ref(), expected, "fixture bytes pin the hash");
        }

        let repo = seed_repo(pool).await;
        let art_b = seed_artifact(pool, repo, "window-b", HASH_B, Some("released")).await;
        let art_c = seed_artifact(pool, repo, "window-c", HASH_C, Some("released")).await;
        for (art, hash) in [(art_b, HASH_B), (art_c, HASH_C)] {
            sqlx::query("DELETE FROM content_references WHERE source_artifact_id = $1")
                .bind(art)
                .execute(pool)
                .await
                .unwrap();
            insert_cr(pool, repo, art, "primary_content", hash).await;
            append_expired_with_reason(pool, art, 0, reason.clone()).await;
        }

        // The page comes back ordered by `artifact_id`, so which of the
        // two is the leader is decided by the ids the fixture happened
        // to get.
        let (leader, victim) = if art_b < art_c {
            (art_b, art_c)
        } else {
            (art_c, art_b)
        };
        let hash_of = |art: Uuid| if art == art_b { HASH_B } else { HASH_C };
        (
            repo,
            storage,
            tmp,
            leader,
            hash_of(leader),
            victim,
            hash_of(victim),
        )
    }

    /// Whether an artifact's stream carries an `ArtifactPurged`, and
    /// whether its `ArtifactExpired` work item is still on it.
    async fn stream_shape(pool: &PgPool, artifact: Uuid) -> (bool, bool) {
        let stream = StreamId::artifact(artifact).to_string();
        let purged: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM events WHERE stream_id = $1 AND event_type = 'ArtifactPurged'",
        )
        .bind(&stream)
        .fetch_one(pool)
        .await
        .unwrap();
        let expired: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM events WHERE stream_id = $1 AND event_type = 'ArtifactExpired'",
        )
        .bind(&stream)
        .fetch_one(pool)
        .await
        .unwrap();
        (purged > 0, expired > 0)
    }

    async fn deleted_at_of(pool: &PgPool, artifact: Uuid) -> Option<DateTime<Utc>> {
        sqlx::query_scalar("SELECT deleted_at FROM artifacts WHERE id = $1")
            .bind(artifact)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    /// `true` iff a reconcile sweep of `repo` proposes no repair naming
    /// `artifact` — i.e. the refcount repair would not put this
    /// artifact's `content_references` edge back.
    ///
    /// The mint candidates filter `deleted_at IS NULL`, so this is
    /// really a question about the retirement: an expired artifact whose
    /// edge the purge has deleted but whose row is still live is exactly
    /// the shape the repair mints for, and a re-minted edge makes the
    /// hash's refcount non-zero under the blob lock — so the purge keeps
    /// the blob and finishes, leaving an orphan edge on an artifact that
    /// is on its way out of service and bytes nothing will collect
    /// again.
    async fn reconcile_proposes_no_repair_for(pool: &PgPool, repo: Uuid, artifact: Uuid) -> bool {
        use hort_domain::ports::refcount_reconcile::RefcountRepair;

        crate::refcount_reconcile::PgRefcountReconcile::new(pool.clone())
            .scan_repo_drift(repo)
            .await
            .unwrap()
            .repairs
            .iter()
            .all(|repair| match repair {
                RefcountRepair::CreatePrimaryContent {
                    source_artifact_id, ..
                }
                | RefcountRepair::RepairPrimaryContent {
                    source_artifact_id, ..
                }
                | RefcountRepair::UpsertMetadataBlob {
                    source_artifact_id, ..
                }
                | RefcountRepair::DeleteRejectedSourceRows {
                    source_artifact_id, ..
                } => *source_artifact_id != artifact,
            })
    }

    async fn updated_at_of(pool: &PgPool, artifact: Uuid) -> DateTime<Utc> {
        sqlx::query_scalar("SELECT updated_at FROM artifacts WHERE id = $1")
            .bind(artifact)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    /// **The finding, half one.** A released artifact is read into the
    /// page as a purge candidate; a scan verdict moves it to a
    /// GC-protected state while the sweep is still working through the
    /// items ahead of it. The page row the sweep carries says
    /// `released`, so every check that reads it agrees the artifact is
    /// collectable — and the preparation transaction deletes its
    /// `content_references` edges, which is the step that cannot be
    /// taken back: the refcount repair mints no edge for protected
    /// evidence, so nothing will ever put it back.
    ///
    /// Now the facts are re-read under the artifact lock, in the
    /// transaction that would have done the deleting, and the
    /// preparation refuses: no edge, no byte, no event, work item still
    /// pending.
    ///
    /// Removing that re-read turns this red on **"the edges are
    /// gone"** rather than on the bytes — the hash-level claim check
    /// keeps the bytes here, because a freshly-`rejected` artifact is a
    /// protected claimant of its own content. Keeping the artifact's
    /// own record intact is this check's job, and the bytes assertion
    /// is here because the acceptance for "nothing happened" includes
    /// them.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn a_status_that_turns_protected_inside_the_window_is_refused_under_the_lock() {
        let Some(pool) = maybe_pool().await else {
            return;
        };

        for status in ["rejected", "scan_indeterminate", "quarantined"] {
            let (repo, storage, _tmp, leader, leader_hash, victim, victim_hash) =
                two_artifacts_one_window(&pool, keep_last_n_reason()).await;

            // Fires during the leader's preparation — after the page
            // read, before the victim's.
            let mutating_pool = pool.clone();
            let gc = MutateAfterFirstPrepare::new(
                adapter(&pool).await,
                Box::new(move || {
                    Box::pin(async move {
                        sqlx::query("UPDATE artifacts SET quarantine_status = $2 WHERE id = $1")
                            .bind(victim)
                            .bind(status)
                            .execute(&mutating_pool)
                            .await
                            .expect("scan verdict lands mid-sweep");
                    })
                }),
            );

            let uc = PurgeUseCase::new(Arc::new(gc), storage.clone(), Arc::new(ConvergedGate));
            let summary = uc.process_expired(Utc::now()).await.expect("sweep runs");

            // Nothing happened to the victim. Asserted before the
            // counters on purpose: with the re-read removed this is
            // the assertion that fails, and "the edges are gone" is
            // the damage — a counter that did not move is only its
            // symptom.
            assert_eq!(
                cr_rows_for(&pool, victim).await,
                vec![("primary_content".to_owned(), victim_hash.to_owned())],
                "{status}: the evidence keeps its reference edge — nothing \
                 re-mints one for a protected artifact"
            );
            assert!(
                storage.exists(&victim_hash.parse().unwrap()).await.unwrap(),
                "{status}: the evidence keeps its bytes"
            );
            assert_eq!(
                deleted_at_of(&pool, victim).await,
                None,
                "{status}: the evidence row stays live"
            );
            assert_eq!(
                stream_shape(&pool, victim).await,
                (false, true),
                "{status}: no ArtifactPurged, and the work item is retained \
                 so the next sweep asks again"
            );

            assert_eq!(
                summary.skipped_protected_under_lock, 1,
                "{status}: the re-read under the lock is what caught it"
            );
            assert_eq!(
                summary.skipped_protected, 0,
                "{status}: the page row said released, so the pre-exit \
                 could not have caught it — if this moved, the fixture is \
                 not testing the window"
            );
            assert_eq!(summary.errors, 0, "{status}: a refusal is not an error");

            // And the leader — whose facts did not move — was purged
            // normally, so the refusal is about this artifact and not
            // about the sweep losing its nerve.
            assert!(
                cr_rows_for(&pool, leader).await.is_empty(),
                "{status}: the unchanged sibling released its edge"
            );
            assert!(
                !storage.exists(&leader_hash.parse().unwrap()).await.unwrap(),
                "{status}: the unchanged sibling's bytes were collected"
            );
            assert_eq!(summary.blobs_deleted, 1, "{status}");

            cleanup(&pool, repo).await;
        }
    }

    /// **The finding, half two.** Same window, the other rule: a
    /// mutable ref comes to resolve to a `KeepLastN`-expired artifact
    /// while the sweep is working through the items ahead of it. Here
    /// the page row's staleness costs the **bytes** — the artifact is
    /// `released`, so the hash-level claim check finds no protected
    /// claimant, grants the lease and deletes the CAS object the live
    /// tag resolves to.
    ///
    /// Removing the re-read turns this red on "the bytes are gone".
    /// The rule applied is `PendingPurge::is_tag_exempt` — the same
    /// predicate the page-row pre-exit uses, not a second copy of it.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn a_tag_that_lands_inside_the_window_is_refused_under_the_lock() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let (repo, storage, _tmp, leader, leader_hash, victim, victim_hash) =
            two_artifacts_one_window(&pool, keep_last_n_reason()).await;

        let mutating_pool = pool.clone();
        let gc = MutateAfterFirstPrepare::new(
            adapter(&pool).await,
            Box::new(move || {
                Box::pin(async move {
                    sqlx::query(
                        r#"INSERT INTO mutable_refs (
                               repository_id, namespace, ref_name, target_kind, target_hash
                           ) VALUES ($1, 'window-tag', 'latest', 'hash', $2)"#,
                    )
                    .bind(repo)
                    .bind(victim_hash)
                    .execute(&mutating_pool)
                    .await
                    .expect("a tag is set mid-sweep");
                })
            }),
        );

        let uc = PurgeUseCase::new(Arc::new(gc), storage.clone(), Arc::new(ConvergedGate));
        let summary = uc.process_expired(Utc::now()).await.expect("sweep runs");

        // The bytes first, for the same reason as in the status test:
        // with the re-read removed this is the assertion that fails,
        // and here the damage really is the CAS object — nothing holds
        // these bytes but a live tag, and the sweep granted itself a
        // lease over them.
        assert!(
            storage.exists(&victim_hash.parse().unwrap()).await.unwrap(),
            "the bytes the live tag resolves to must survive"
        );
        assert_eq!(
            cr_rows_for(&pool, victim).await,
            vec![("primary_content".to_owned(), victim_hash.to_owned())],
            "and its reference edge with them"
        );
        assert_eq!(
            deleted_at_of(&pool, victim).await,
            None,
            "the tag target stays live"
        );
        assert_eq!(
            stream_shape(&pool, victim).await,
            (false, true),
            "no ArtifactPurged; the ArtifactExpired is retained and the \
             artifact is purged once the tag moves"
        );

        assert_eq!(
            summary.skipped_tag_exempt_under_lock, 1,
            "the re-read under the lock is what caught it"
        );
        assert_eq!(
            summary.skipped_tag_exempt, 0,
            "the page row carried no ref, so the pre-exit could not have \
             caught it — if this moved, the fixture is not testing the window"
        );
        assert_eq!(summary.errors, 0, "a refusal is not an error");

        assert!(
            cr_rows_for(&pool, leader).await.is_empty(),
            "the untagged sibling released its edge"
        );
        assert!(
            !storage.exists(&leader_hash.parse().unwrap()).await.unwrap(),
            "the untagged sibling's bytes were collected"
        );
        assert_eq!(summary.blobs_deleted, 1);

        cleanup(&pool, repo).await;
    }

    /// The counter-test to both of the above: a status write inside the
    /// same window that is **not** protective leaves the purge alone.
    /// Without this, a re-read that refused unconditionally — or one
    /// that could not classify `released` — would pass the two tests
    /// above and brake the whole sweep.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn an_artifact_whose_window_changes_nothing_relevant_is_purged_normally() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let (repo, storage, _tmp, leader, leader_hash, victim, victim_hash) =
            two_artifacts_one_window(&pool, keep_last_n_reason()).await;

        let mutating_pool = pool.clone();
        let gc = MutateAfterFirstPrepare::new(
            adapter(&pool).await,
            Box::new(move || {
                Box::pin(async move {
                    // A real write to the very column the re-read
                    // consults, landing in the window, that does not
                    // protect anything.
                    sqlx::query(
                        "UPDATE artifacts SET quarantine_status = 'released' WHERE id = $1",
                    )
                    .bind(victim)
                    .execute(&mutating_pool)
                    .await
                    .expect("a benign status write lands mid-sweep");
                })
            }),
        );

        let uc = PurgeUseCase::new(Arc::new(gc), storage.clone(), Arc::new(ConvergedGate));
        let summary = uc.process_expired(Utc::now()).await.expect("sweep runs");

        assert_eq!(summary.artifacts_visited, 2);
        assert_eq!(summary.blobs_deleted, 2, "both artifacts were collected");
        assert_eq!(summary.skipped_protected_under_lock, 0);
        assert_eq!(summary.skipped_tag_exempt_under_lock, 0);
        assert_eq!(summary.skipped_protected, 0);
        assert_eq!(summary.skipped_tag_exempt, 0);
        assert_eq!(summary.errors, 0);

        for (art, hash) in [(leader, leader_hash), (victim, victim_hash)] {
            assert!(cr_rows_for(&pool, art).await.is_empty(), "{art}: edge gone");
            assert!(
                !storage.exists(&hash.parse().unwrap()).await.unwrap(),
                "{art}: bytes collected"
            );
            assert!(deleted_at_of(&pool, art).await.is_some(), "{art}: retired");
            assert_eq!(stream_shape(&pool, art).await, (true, true), "{art}");
        }

        cleanup(&pool, repo).await;
    }

    /// The re-read guards the **first** destructive step, and a retry
    /// is past it: once a worklist exists the edges are already gone,
    /// so the facts are deliberately not consulted again.
    ///
    /// Declining there would strand the artifact — edges deleted, no
    /// terminal event appendable, purge never finishable — and what
    /// protects the bytes from this point on is `begin_blob_reclaim`'s
    /// claim check, which asks about the hash rather than the artifact
    /// and so sees the freshly-protected row as a claimant.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn a_retry_reads_the_worklist_and_not_the_facts_again() {
        let Some(pool) = maybe_pool().await else {
            return;
        };
        let repo = seed_repo(&pool).await;
        let art = seed_artifact(&pool, repo, "already-prepared", HASH_A, Some("released")).await;
        sqlx::query("DELETE FROM content_references WHERE source_artifact_id = $1")
            .bind(art)
            .execute(&pool)
            .await
            .unwrap();
        insert_cr(&pool, repo, art, "primary_content", HASH_A).await;
        append_event(&pool, art, "ArtifactExpired", 0).await;

        let adapter = adapter(&pool).await;
        let first = prepared(adapter.purge_artifact_refs(art, Utc::now()).await.unwrap());
        assert_eq!(first.len(), 1);

        sqlx::query("UPDATE artifacts SET quarantine_status = 'rejected' WHERE id = $1")
            .bind(art)
            .execute(&pool)
            .await
            .unwrap();

        assert_eq!(
            prepared(adapter.purge_artifact_refs(art, Utc::now()).await.unwrap()),
            first,
            "the committed worklist is the authoritative target set; a \
             refusal here would leave a purge that can never finish"
        );

        cleanup(&pool, repo).await;
    }
}
