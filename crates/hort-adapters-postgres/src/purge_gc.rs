//! PostgreSQL adapter for [`PurgeGcPort`] — the storage-GC walk
//! (`PurgeUseCase::process_expired`, ADR 0020 §4 + §5).
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
//!   This is re-read here, not inherited from the evaluation sweep:
//!   the two sweeps are an hour apart and a tag set in between arrives
//!   after the `ArtifactExpired` is already on the stream.
//! - `expired_only_by_keep_last_n` — no pending `ArtifactExpired` on
//!   the stream carries a readable non-`KeepLastN` reason.
//!   `ExpirationReason` is an externally-tagged enum, so the stored
//!   payload of a count-based expiry is `{"KeepLastN": {…}}` under
//!   `event_data->'data'->'reason'`. The exemption belongs to
//!   `KeepLastN` alone — an age- or security-driven decision is not
//!   countermanded by a tag.
//!
//!   The `jsonb_typeof(…) = 'object'` guard is the fail-safe
//!   direction: only a payload that positively reads as *some other*
//!   reason clears the exemption. An absent or non-object reason
//!   leaves the flag set, which at worst withholds a destructive step
//!   on an artifact a tag currently names — visible in the sweep
//!   summary and released as soon as the tag moves. The opposite
//!   default would let an unreadable payload delete content a live
//!   tag resolves to, and deletion does not come back.
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
//! 2. `DELETE FROM content_references WHERE source_artifact_id = $1
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
//! it. Zero still ⇒ a `BlobReclaim::Granted` guard the caller holds
//! across `StoragePort::delete`. Non-zero ⇒ `Referenced`, with the
//! worklist row corrected in place so the terminal event states the
//! count that held. Lock busy ⇒ `Contended`, and nothing is read or
//! changed.
//!
//! Every production `content_references` write takes the same lock
//! (`pg_content_reference_repo::insert`, `refcount_reconcile`'s repair
//! upsert), which is what makes the re-read conclusive rather than just
//! fresher.
//!
//! After storage decisions have been checkpointed per worklist row,
//! `complete_artifact_purge` appends the whole per-hash terminal event
//! batch and writes `artifacts.deleted_at` in one transaction. The
//! projection and stream therefore cannot expose different terminal
//! states.
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
    BlobReclaim, BlobReclaimGuard, PendingPurge, PurgeGcPort, PurgedRef,
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
            // case re-asserts the same filter defence-in-depth. A
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
                       NOT EXISTS (
                         SELECT 1 FROM events e
                          WHERE e.stream_id  = 'artifact-' || a.id::text
                            AND e.event_type = 'ArtifactExpired'
                            AND jsonb_typeof(e.event_data->'data'->'reason')
                                  = 'object'
                            AND NOT (e.event_data->'data'->'reason'
                                       ? 'KeepLastN')
                       )                   AS expired_only_by_keep_last_n,
                       EXISTS (
                         SELECT 1 FROM events e
                          WHERE e.stream_id  = 'artifact-' || a.id::text
                            AND e.event_type = 'ArtifactDeleted'
                       )                   AS user_deleted
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
            );
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
    ) -> BoxFuture<'_, DomainResult<Vec<PurgedRef>>> {
        Box::pin(async move {
            let mut tx = self.pool.begin().await.map_err(|e| {
                DomainError::Invariant(format!("purge_gc purge_artifact_refs begin: {e}"))
            })?;

            let existing = Self::load_worklist(&mut tx, artifact_id).await?;
            if !existing.is_empty() {
                tx.commit().await.map_err(|e| {
                    DomainError::Invariant(format!("purge_gc worklist-read commit: {e}"))
                })?;
                return Self::map_worklist(existing);
            }

            // Locking serializes first-time preparation. Once a
            // worklist exists, it is the authoritative target set and
            // no deleted edge needs to be reconstructed. The initial
            // worklist read happens before this artifact lock so a
            // normal retry cannot invert the final transition's
            // worklist -> events -> artifact lock order.
            let locked: Option<(String,)> =
                sqlx::query_as("SELECT checksum_sha256 FROM artifacts WHERE id = $1 FOR UPDATE")
                    .bind(artifact_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(|e| map_sqlx_error(&e, "purge_gc", "lock_artifact"))?;
            let Some((checksum_sha256,)) = locked else {
                tx.commit().await.map_err(|e| {
                    DomainError::Invariant(format!("purge_gc commit (no-artifact): {e}"))
                })?;
                return Ok(Vec::new());
            };

            // Another first-time preparer may have committed while this
            // transaction waited for the artifact lock.
            let existing = Self::load_worklist(&mut tx, artifact_id).await?;
            if !existing.is_empty() {
                tx.commit().await.map_err(|e| {
                    DomainError::Invariant(format!("purge_gc worklist-read commit: {e}"))
                })?;
                return Self::map_worklist(existing);
            }

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
            Self::map_worklist(worklist)
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
                let updated = sqlx::query(
                    "UPDATE artifact_purge_worklist SET refs_remaining = $3 \
                     WHERE artifact_id = $1 AND content_hash = $2",
                )
                .bind(artifact_id)
                .bind(hash.as_ref())
                .bind(i64::from(refs_now))
                .execute(&mut *tx)
                .await
                .map_err(|e| map_sqlx_error(&e, "purge_gc", "refresh_worklist_refs"))?;
                if updated.rows_affected() != 1 {
                    return Err(DomainError::Invariant(format!(
                        "purge_gc: no worklist row for artifact {artifact_id} hash {hash}"
                    )));
                }
                tx.commit().await.map_err(|e| {
                    DomainError::Invariant(format!("purge_gc blob-lock refresh commit: {e}"))
                })?;
                return Ok(BlobReclaim::Referenced { refs_now });
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
            // end up retired, whoever retired it. A user-facing delete
            // can land between the expiry decision and this sweep (the
            // pending-purge set has no `deleted_at` predicate), and an
            // unconditional `deleted_at IS NULL` guard would then fail
            // this transition on every retry, leaving an artifact whose
            // blobs are gone, whose row lives, and whose stream carries
            // no terminal event. `COALESCE` keeps the *earlier*
            // timestamp: the moment the artifact left service is the
            // audit fact, and overwriting it with the purge time would
            // erase it. Matching on `id` alone still affects zero rows —
            // and so still yields `NotFound` — when the row is genuinely
            // absent.
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
        let mut refs = adapter.purge_artifact_refs(art).await.unwrap();
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
        let refs = adapter.purge_artifact_refs(art).await.unwrap();
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
        let refs = adapter.purge_artifact_refs(purged).await.unwrap();
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

        // First invocation deletes the rows and returns both decisions.
        let first = adapter.purge_artifact_refs(art).await.unwrap();
        assert_eq!(first.len(), 2);
        assert!(cr_rows_for(&pool, art).await.is_empty());

        // Second invocation: rows are gone. The hashes are recovered
        // from artifacts.checksum_sha256 + artifact_metadata.metadata_blob
        // and the count (stable at 0) is recomputed — the retry still
        // yields the decisions needed to finish the purge.
        let mut second = adapter.purge_artifact_refs(art).await.unwrap();
        second.sort_by(|a, b| a.content_hash.as_ref().cmp(b.content_hash.as_ref()));
        assert_eq!(second.len(), 2, "idempotent retry recovers both hashes");
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
        let refs = adapter.purge_artifact_refs(child_a).await.unwrap();
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
        let refs_after = adapter.purge_artifact_refs(later_child).await.unwrap();
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
        let config_refs = adapter.purge_artifact_refs(config).await.unwrap();
        assert_eq!(config_refs.len(), 1);
        assert_eq!(config_refs[0].content_hash.as_ref(), HASH_A);
        assert_eq!(
            config_refs[0].refs_remaining, 1,
            "a live manifest keeps its config blob (cross-kind count)"
        );
        let layer_refs = adapter.purge_artifact_refs(layer).await.unwrap();
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
        let config_refs_after = adapter.purge_artifact_refs(later_config).await.unwrap();
        assert_eq!(config_refs_after.len(), 1);
        assert_eq!(config_refs_after[0].content_hash.as_ref(), HASH_A);
        assert_eq!(
            config_refs_after[0].refs_remaining, 0,
            "once the manifest is deleted, its config blob is GC-eligible"
        );
        let layer_refs_after = adapter.purge_artifact_refs(later_layer).await.unwrap();
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
            let refs_1 = adapter.purge_artifact_refs(manifest_1).await.unwrap();
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
            let refs_2 = adapter.purge_artifact_refs(manifest_2).await.unwrap();
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
        let prepared = adapter.purge_artifact_refs(artifact).await.unwrap();
        assert_eq!(prepared.len(), 2);
        assert!(cr_rows_for(&pool, artifact).await.is_empty());

        adapter
            .mark_purge_ref_complete(artifact, &HASH_A.parse().unwrap(), Utc::now())
            .await
            .unwrap();
        let retry = adapter.purge_artifact_refs(artifact).await.unwrap();
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
        let deleted_at: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT deleted_at FROM artifacts WHERE id = $1")
                .bind(artifact)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(deleted_at.is_none());
        let first_events: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM events WHERE stream_id = $1 AND event_type = 'ArtifactPurged'",
        )
        .bind(StreamId::artifact(artifact).to_string())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(first_events, 0);

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
        let refs = adapter.purge_artifact_refs(artifact).await.unwrap();
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

        let deleted_at: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT deleted_at FROM artifacts WHERE id = $1")
                .bind(artifact)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(deleted_at.is_none());

        cleanup(&pool, repo).await;
    }

    /// Terminal events and projection retirement are one commit. The
    /// injected interruption happens after the append was staged and
    /// proves that dropping the transaction exposes neither half.
    #[tokio::test]
    #[serial(hort_pg_db)]
    async fn interrupted_terminal_transition_exposes_neither_event_nor_retirement() {
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
        let refs = adapter.purge_artifact_refs(artifact).await.unwrap();
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
        assert!(deleted_at.is_none());
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
        let refs = adapter.purge_artifact_refs(expired).await.unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].refs_remaining, 1);
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

        let drift = crate::refcount_reconcile::PgRefcountReconcile::new(pool.clone())
            .scan_repo_drift(repo)
            .await
            .unwrap();
        assert!(drift.repairs.iter().all(|repair| match repair {
            hort_domain::ports::refcount_reconcile::RefcountRepair::CreatePrimaryContent {
                source_artifact_id,
                ..
            }
            | hort_domain::ports::refcount_reconcile::RefcountRepair::RepairPrimaryContent {
                source_artifact_id,
                ..
            }
            | hort_domain::ports::refcount_reconcile::RefcountRepair::UpsertMetadataBlob {
                source_artifact_id,
                ..
            }
            | hort_domain::ports::refcount_reconcile::RefcountRepair::DeleteRejectedSourceRows {
                source_artifact_id,
                ..
            } => *source_artifact_id != expired,
        }));
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

        let refs = adapter.purge_artifact_refs(art).await.unwrap();
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
        let refs = adapter.purge_artifact_refs(old).await.unwrap();
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
        let refs = adapter.purge_artifact_refs(Uuid::new_v4()).await.unwrap();
        assert!(refs.is_empty(), "no artifact row → nothing to purge");
    }

    // -- tag exemption, re-asked at purge time ---------------------------

    /// Walk the interval the two cron sweeps leave open. At 03:00 the
    /// evaluator expired an untagged artifact under `KeepLastN`; at
    /// 03:30 an operator tagged it; the purge runs at 04:00 and nothing
    /// re-ran the predicate. The work-set read is what has to notice.
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

        // 04:00 — the purge sweep re-reads the work set.
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
            .purge_artifact_refs(art)
            .await
            .expect("worklist prepared");
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

    /// The lease's three answers, straight from the adapter: granted on
    /// a free lock over an unreferenced hash, `Referenced` (with the
    /// worklist row corrected in place) once a reference exists, and
    /// `Contended` while someone else holds the lock.
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
}
