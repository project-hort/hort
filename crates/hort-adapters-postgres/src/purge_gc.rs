//! PostgreSQL adapter for [`PurgeGcPort`] — the storage-GC walk
//! (`PurgeUseCase::process_expired`, ADR 0020 §4 + §5).
//!
//! Runs the refcount-GC algorithm against the eventually-authoritative
//! `content_references` refcount projection (safe only behind the
//! `RefcountReconcileUseCase` convergence gate the use case
//! enforces — see the port module docs
//! (`hort-domain/src/ports/purge_gc.rs`) for the posture this consumes).
//!
//! Purely additive: a brand-new adapter for a brand-new (additive)
//! port. No existing adapter or port signature is touched. The
//! existing [`crate::pg_content_reference_repo::PgContentReferenceRepo`]
//! and [`crate::refcount_reconcile::PgRefcountReconcile`] are left
//! exactly as shipped.
//!
//! # `list_pending_purge`
//!
//! Every artifact whose stream (`stream_id = 'artifact-' || a.id`) has
//! an `ArtifactExpired` event and **no** `ArtifactPurged` event — the
//! pending purge work set. `quarantine_status ∈ {quarantined,
//! rejected, scan_indeterminate}` is excluded (evidence is
//! GC-protected); the use case re-asserts the same invariant
//! defence-in-depth, but the adapter never hands a protected artifact
//! to the destructive path in the first place.
//!
//! # `purge_artifact_refs` — three steps in one committed tx
//!
//! 1. `SELECT … FROM artifacts WHERE id = $1 FOR UPDATE` — lock the
//!    artifact row so a concurrent ingest/promote cannot race the
//!    refcount decrement; also recovers the authoritative
//!    `checksum_sha256` for the idempotent-retry path.
//! 2. `DELETE FROM content_references WHERE source_artifact_id = $1
//!    RETURNING target_content_hash` — remove **every** kind of this
//!    artifact's own source-edges: the `primary_content` /
//!    `metadata_blob` refcount rows AND (#49) any `oci_index_member` /
//!    `oci_subject` / `oci_config` / `oci_layer` membership edges this
//!    artifact carries as a source (e.g. an image index's children, or
//!    a manifest's config/layer blobs). Purge tombstones the `artifacts`
//!    row rather than hard-deleting it, so the FK's `ON DELETE CASCADE`
//!    never fires for a purge — this DELETE is the only sweep that
//!    reaches a purged manifest's membership edges. Mirrors
//!    `pg_content_reference_repo::delete_by_source`'s all-kinds
//!    behavior (the manifest-DELETE path), now applied to purge too.
//! 3. For each distinct returned hash `H`:
//!    `SELECT count(*) FROM content_references WHERE
//!    target_content_hash = H` — the **cross-`kind`** remaining count
//!    (covers `oci_subject` / `oci_index_member` / `oci_config` /
//!    `oci_layer` too: a live OCI manifest/index still pointing at `H`
//!    keeps the blob alive even when the artifact whose primary content
//!    matches `H` is purged).
//!
//! **Idempotent retry.** If a prior partial run already committed the
//! `DELETE` (storage delete / `ArtifactPurged` append then failed and
//! the sweep retries), step 2 returns zero rows. `primary_content` and
//! `metadata_blob` are recovered from the authoritative columns —
//! `artifacts.checksum_sha256` (locked in step 1) and
//! `artifact_metadata.metadata_blob` — and the now-stable cross-`kind`
//! count is recomputed for those. **The `oci_*` membership targets are
//! NOT recovered on retry** (#49, accepted bounded gap — see the code
//! comment at the recovery branch): there is no authoritative column to
//! reconstruct them from, and by the time the retry runs, their
//! refcounts are already correctly decremented from the prior attempt's
//! committed DELETE — only this retry call's own `PurgedRef` output
//! (decision emission) omits them, not the underlying data.
//!
//! `metadata_blob` is stored as `character(64)` (blank-padded) on
//! `artifact_metadata`; it is trimmed at the boundary before parsing,
//! mirroring `pg_content_reference_repo::row_to_reference` /
//! `refcount_reconcile::parse_hash`.

use std::collections::BTreeMap;
use std::str::FromStr;

use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

use hort_domain::entities::artifact::QuarantineStatus;
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::purge_gc::{PendingPurge, PurgeGcPort, PurgedRef};
use hort_domain::types::ContentHash;

use crate::{map_sqlx_error, BoxFuture};

/// PostgreSQL implementation of [`PurgeGcPort`].
///
/// Thin wrapper over a `PgPool`; no per-instance state beyond the
/// pool. Construction is cheap (no I/O).
pub struct PgPurgeGcPort {
    pool: PgPool,
}

impl PgPurgeGcPort {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// One pending-purge artifact: it has an `ArtifactExpired` event with
/// no following `ArtifactPurged`, and is not in a GC-protected
/// quarantine state.
#[derive(Debug, FromRow)]
struct PendingRow {
    artifact_id: Uuid,
    quarantine_status: Option<String>,
}

/// One `(target_content_hash, kind)` row removed by the step-2
/// `DELETE … RETURNING`, or recovered from the authoritative columns
/// on an idempotent retry.
#[derive(Debug, FromRow)]
struct DeletedRefRow {
    target_content_hash: String,
}

/// Map the persisted `artifacts.quarantine_status` text to the domain
/// [`QuarantineStatus`]. The GC-protected set is filtered in SQL, so
/// any value the use case re-checks must round-trip; an unknown value
/// is a data-integrity error rather than a silent mis-classification of
/// a destructive decision.
fn map_status(raw: Option<&str>) -> DomainResult<QuarantineStatus> {
    match raw {
        // `unscanned` / `clean` / `flagged` are non-terminal scan
        // states the schema allows but the artifact aggregate models
        // as `None` (no quarantine gate) — same collapse the rest of
        // the v2 read path uses. They are NOT protected; only
        // quarantined / rejected / scan_indeterminate are.
        None | Some("unscanned") | Some("clean") | Some("flagged") | Some("none") => {
            Ok(QuarantineStatus::None)
        }
        Some("quarantined") => Ok(QuarantineStatus::Quarantined),
        Some("released") => Ok(QuarantineStatus::Released),
        Some("rejected") => Ok(QuarantineStatus::Rejected),
        Some("scan_indeterminate") => Ok(QuarantineStatus::ScanIndeterminate),
        Some(other) => Err(DomainError::Invariant(format!(
            "purge_gc: unknown quarantine_status {other:?} on a pending-purge artifact"
        ))),
    }
}

/// Parse a DB hash column into a [`ContentHash`], trimming the
/// blank-padding `character(64)` columns carry. A corrupt value is a
/// data-integrity error (mirrors `refcount_reconcile::parse_hash`).
fn parse_hash(raw: &str, ctx: &str) -> DomainResult<ContentHash> {
    ContentHash::from_str(raw.trim())
        .map_err(|_| DomainError::Invariant(format!("purge_gc: corrupt hash {raw:?} ({ctx})")))
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
}

impl PurgeGcPort for PgPurgeGcPort {
    fn list_pending_purge(&self) -> BoxFuture<'_, DomainResult<Vec<PendingPurge>>> {
        Box::pin(async move {
            // An artifact stream serializes as `artifact-<uuid>`
            // (`StreamId::Display`). The pending-purge set is every
            // artifact whose stream has an `ArtifactExpired` and no
            // `ArtifactPurged`. Protected quarantine states are
            // excluded here (GC-protected invariant) — the destructive
            // path is never even offered an evidence artifact; the use
            // case re-asserts the same filter defence-in-depth.
            let rows: Vec<PendingRow> = sqlx::query_as(
                r#"
                SELECT a.id                AS artifact_id,
                       a.quarantine_status AS quarantine_status
                  FROM artifacts a
                 WHERE EXISTS (
                         SELECT 1 FROM events e
                          WHERE e.stream_id  = 'artifact-' || a.id::text
                            AND e.event_type = 'ArtifactExpired'
                       )
                   AND NOT EXISTS (
                         SELECT 1 FROM events e
                          WHERE e.stream_id  = 'artifact-' || a.id::text
                            AND e.event_type = 'ArtifactPurged'
                       )
                   AND (a.quarantine_status IS NULL
                        OR a.quarantine_status NOT IN
                           ('quarantined','rejected','scan_indeterminate'))
                 ORDER BY a.id
                "#,
            )
            .fetch_all(&self.pool)
            .await
            .map_err(|e| map_sqlx_error(&e, "purge_gc", "list_pending"))?;

            let mut out = Vec::with_capacity(rows.len());
            for row in rows {
                out.push(PendingPurge {
                    artifact_id: row.artifact_id,
                    quarantine_status: map_status(row.quarantine_status.as_deref())?,
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

            // -- Step 1: lock the artifact row FOR UPDATE -------------
            //
            // Also yields the authoritative `checksum_sha256` for the
            // idempotent-retry recovery path. A missing row means the
            // artifact was hard-deleted out from under the pending
            // `ArtifactExpired` (FK `ON DELETE CASCADE` already swept
            // its content_references); the purge is then a no-op —
            // there is nothing left to decrement.
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

            // -- Step 2: DELETE this artifact's own refs --------------
            //
            // ALL kinds (#49) — no `kind IN (...)` filter. Mirrors
            // `pg_content_reference_repo::delete_by_source`'s all-kinds
            // sweep. Purge tombstones the `artifacts` row (`ArtifactPurged`)
            // rather than hard-`DELETE`ing it, so the `content_references`
            // FK's `ON DELETE CASCADE` never fires for a purge — this
            // DELETE is the only thing that removes a purged manifest's
            // `oci_index_member` / `oci_subject` / `oci_config` /
            // `oci_layer` **source**-edges (in addition to its own
            // `primary_content` / `metadata_blob` refcount rows). Without
            // sweeping every kind here, a purged manifest's membership
            // edges dangled forever (no cascade, no other sweep reaches
            // them), permanently over-retaining every target they pointed
            // at — the #49 leak.
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

            // Distinct target hashes this artifact referenced, across
            // EVERY kind — the `oci_*` membership targets (child
            // manifests / config / layer blobs) ride the same `hashes`
            // set as `primary_content` / `metadata_blob` from here on,
            // so step 3 recomputes their cross-`kind` remaining count
            // exactly like any other target. On the happy path these
            // come from the DELETE … RETURNING above; on an idempotent
            // retry (a prior run already committed the DELETE) the set
            // is empty and is recovered from the authoritative
            // `artifacts.checksum_sha256` + `artifact_metadata.metadata_blob`
            // columns.
            let mut hashes: BTreeMap<String, ContentHash> = BTreeMap::new();
            for row in &deleted {
                let h = parse_hash(
                    &row.target_content_hash,
                    "content_references.target_content_hash",
                )?;
                hashes.insert(h.as_ref().to_owned(), h);
            }
            if hashes.is_empty() {
                // Idempotent-retry recovery: the rows were already
                // deleted by a prior partial run. Recover from the
                // authoritative columns so the retry still produces
                // the decisions needed to finish the purge.
                //
                // **Accepted bounded gap (#49):** this recovery ONLY
                // reconstructs `primary_content` (from
                // `artifacts.checksum_sha256`) and `metadata_blob` (from
                // `artifact_metadata.metadata_blob`) — there is no
                // authoritative column anywhere that records what
                // `oci_index_member` / `oci_subject` / `oci_config` /
                // `oci_layer` **targets** this artifact's now-deleted
                // membership edges used to point at, so those targets are
                // NOT re-added to `hashes` on a retry. This does not
                // reintroduce the #49 leak: by the time this branch runs,
                // the DELETE in step 2 already committed on the prior
                // attempt, so every `oci_*` target's refcount is already
                // correctly decremented in the database — the gap is
                // purely that THIS retry's `PurgedRef` output (and thus
                // the use case's GC-eligibility decision emission for
                // that call) skips those already-corrected targets. A
                // later, unrelated purge/reconcile pass still sees their
                // true (already-decremented) count. Deliberately not
                // fixed by adding a column/table for this bounded,
                // rare-partial-failure gap (directive #49 — do not expand
                // the schema for it); revisit only if evidence shows the
                // retry path is common enough to matter.
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

            // -- Step 3: cross-`kind` remaining count per hash --------
            let mut out = Vec::with_capacity(hashes.len());
            for hash in hashes.into_values() {
                let refs_remaining = Self::remaining_refs(&mut tx, &hash).await?;
                out.push(PurgedRef {
                    content_hash: hash,
                    refs_remaining,
                });
            }

            // -- Step 4: commit ---------------------------------------
            tx.commit().await.map_err(|e| {
                DomainError::Invariant(format!("purge_gc purge_artifact_refs commit: {e}"))
            })?;
            Ok(out)
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    const HASH_A: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const HASH_B: &str = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
    const HASH_C: &str = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae";

    // -- pure unit -----------------------------------------------------

    #[test]
    fn adapter_implements_port() {
        fn _assert_port<T: PurgeGcPort>() {}
        _assert_port::<PgPurgeGcPort>();
    }

    #[tokio::test]
    async fn pg_purge_gc_new_does_not_panic() {
        let pool = PgPool::connect_lazy("postgres://localhost/nonexistent")
            .expect("connect_lazy validates only the URL, not connectivity");
        let _ = PgPurgeGcPort::new(pool);
    }

    #[test]
    fn map_status_maps_known_values_and_collapses_scan_states() {
        assert_eq!(map_status(None).unwrap(), QuarantineStatus::None);
        assert_eq!(
            map_status(Some("unscanned")).unwrap(),
            QuarantineStatus::None
        );
        assert_eq!(map_status(Some("clean")).unwrap(), QuarantineStatus::None);
        assert_eq!(map_status(Some("flagged")).unwrap(), QuarantineStatus::None);
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

    #[test]
    fn map_status_rejects_unknown() {
        let err = map_status(Some("bogus")).unwrap_err();
        assert!(matches!(err, DomainError::Invariant(_)));
        assert!(err.to_string().contains("unknown quarantine_status"));
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
        sqlx::migrate!("../../migrations")
            .run(&pool)
            .await
            .expect("migrations run cleanly against the test DB");
        Some(pool)
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
    #[ignore = "requires DATABASE_URL"]
    async fn pending_set_excludes_protected_states() {
        let pool = maybe_pool()
            .await
            .expect("DATABASE_URL required for this test");
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

        let adapter = PgPurgeGcPort::new(pool.clone());
        let pending = adapter.list_pending_purge().await.unwrap();
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
    #[ignore = "requires DATABASE_URL"]
    async fn primary_and_metadata_blob_both_walked() {
        let pool = maybe_pool()
            .await
            .expect("DATABASE_URL required for this test");
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

        let adapter = PgPurgeGcPort::new(pool.clone());
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
    #[ignore = "requires DATABASE_URL"]
    async fn refcount_zero_when_unreferenced() {
        let pool = maybe_pool()
            .await
            .expect("DATABASE_URL required for this test");
        let repo = seed_repo(&pool).await;
        let art = seed_artifact(&pool, repo, "solo", HASH_A, Some("released")).await;
        sqlx::query("DELETE FROM content_references WHERE source_artifact_id = $1")
            .bind(art)
            .execute(&pool)
            .await
            .unwrap();
        insert_cr(&pool, repo, art, "primary_content", HASH_A).await;
        append_event(&pool, art, "ArtifactExpired", 0).await;

        let adapter = PgPurgeGcPort::new(pool.clone());
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
    #[ignore = "requires DATABASE_URL"]
    async fn live_oci_subject_keeps_blob_refs_remaining_gt_zero() {
        let pool = maybe_pool()
            .await
            .expect("DATABASE_URL required for this test");
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

        let adapter = PgPurgeGcPort::new(pool.clone());
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
    #[ignore = "requires DATABASE_URL"]
    async fn idempotent_reinvocation_after_rows_deleted() {
        let pool = maybe_pool()
            .await
            .expect("DATABASE_URL required for this test");
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

        let adapter = PgPurgeGcPort::new(pool.clone());

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
    #[ignore = "requires DATABASE_URL"]
    async fn live_index_member_keeps_child_blob_then_frees_it() {
        let pool = maybe_pool()
            .await
            .expect("DATABASE_URL required for this test");
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

        let adapter = PgPurgeGcPort::new(pool.clone());

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

        // -- Phase 2: index no longer references the child → child freed -
        // The index's own DELETE / purge sweeps every `source = index`
        // row (both members). With no remaining reference to HASH_A, a
        // re-purge of child_a reports the blob GC-eligible.
        sqlx::query("DELETE FROM content_references WHERE source_artifact_id = $1")
            .bind(index)
            .execute(&pool)
            .await
            .unwrap();
        let refs_after = adapter.purge_artifact_refs(child_a).await.unwrap();
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
    #[ignore = "requires DATABASE_URL"]
    async fn live_manifest_blob_edges_keep_config_and_layer_blobs_then_free_them() {
        let pool = maybe_pool()
            .await
            .expect("DATABASE_URL required for this test");
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

        let adapter = PgPurgeGcPort::new(pool.clone());

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

        // -- Phase 2: manifest DELETE (delete_by_source) → blobs freed ---
        // Manifest DELETE sweeps every `source = manifest` row (both
        // kinds), same as an index DELETE. With no remaining reference,
        // a re-purge of the config/layer blobs reports them GC-eligible.
        sqlx::query("DELETE FROM content_references WHERE source_artifact_id = $1")
            .bind(manifest)
            .execute(&pool)
            .await
            .unwrap();
        let config_refs_after = adapter.purge_artifact_refs(config).await.unwrap();
        assert_eq!(config_refs_after.len(), 1);
        assert_eq!(config_refs_after[0].content_hash.as_ref(), HASH_A);
        assert_eq!(
            config_refs_after[0].refs_remaining, 0,
            "once the manifest is deleted, its config blob is GC-eligible"
        );
        let layer_refs_after = adapter.purge_artifact_refs(layer).await.unwrap();
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
    #[ignore = "requires DATABASE_URL"]
    async fn purge_manifest_sweeps_all_oci_kinds_and_frees_target_once_unreferenced() {
        let pool = maybe_pool()
            .await
            .expect("DATABASE_URL required for this test");
        let repo = seed_repo(&pool).await;
        let adapter = PgPurgeGcPort::new(pool.clone());

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

    /// A hard-deleted artifact row (FK cascade already swept its refs)
    /// is a clean no-op — nothing left to decrement.
    #[tokio::test]
    #[serial(hort_pg_db)]
    #[ignore = "requires DATABASE_URL"]
    async fn missing_artifact_row_is_a_noop() {
        let pool = maybe_pool()
            .await
            .expect("DATABASE_URL required for this test");
        let adapter = PgPurgeGcPort::new(pool.clone());
        let refs = adapter.purge_artifact_refs(Uuid::new_v4()).await.unwrap();
        assert!(refs.is_empty(), "no artifact row → nothing to purge");
    }
}
