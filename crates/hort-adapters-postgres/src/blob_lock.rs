//! The **CAS-blob reclamation lock** — one Postgres advisory lock per
//! content hash, taken by every path that records a
//! `content_references` row and by the storage-GC walk that destroys
//! the bytes those rows point at.
//!
//! # What it protects
//!
//! CAS deduplicates: the same content hash belongs to as many
//! artifacts as happen to carry those bytes. So an artifact-row lock
//! says nothing about the blob — it is the wrong granularity for a
//! decision about bytes, and the purge's decision *is* about bytes.
//! Without a hash-scoped lock the refcount-zero observation and the
//! `StoragePort::delete` that follows it are two unrelated moments: a
//! concurrent ingest that deduplicates onto the same hash (the bytes
//! are present, so nothing is written) records its reference in
//! between, and the new artifact ends up pointing at bytes that no
//! longer exist.
//!
//! Both sides taking this lock is the whole mechanism. The reference
//! writer takes it in the same transaction as its write, so its row is
//! either committed before the sweep counts (and therefore counted) or
//! blocked until the sweep is done. The sweep takes it *without
//! waiting* and re-counts under it; anything other than "the lock is
//! mine and the count is zero" means leave the bytes alone.
//!
//! # Why an advisory lock and not a row lock
//!
//! There is no row to lock. A content hash with zero references has no
//! `content_references` row by definition — that is exactly the state
//! the sweep acts on — and `artifacts` is the wrong granularity (see
//! above). An advisory lock needs no row to exist and no table to be
//! invented for it to live in.
//!
//! # Keyspace
//!
//! The single-`bigint` advisory keyspace is reserved, workspace-wide,
//! for this lock and nothing else; Postgres keeps it distinct from the
//! two-`int4` space, which stays free for a future unrelated user. The
//! key is the leading 64 bits of the hash itself (see
//! [`blob_lock_key`]).
//!
//! # Scope discipline
//!
//! Both helpers take a `&mut Transaction`, never a pool: an advisory
//! lock taken with `pg_advisory_xact_lock` is released at the end of
//! *that* transaction, whether it commits, rolls back, or the
//! connection dies. A session-scoped lock (`pg_advisory_lock`) would
//! outlive a dropped guard and be inherited by the next borrower of
//! the pooled connection, which is a leak with no upper bound; the
//! transaction-scoped form cannot do that. The cost is that a holder
//! spanning a storage call is a transaction held open across it — see
//! `purge_gc::PgPurgeGcPort::begin_blob_reclaim`, which is the one
//! place that does so deliberately and the only place allowed to.

use sqlx::{Postgres, Transaction};

use hort_domain::error::DomainResult;
use hort_domain::types::ContentHash;

use crate::map_sqlx_error;

/// Derive the advisory-lock key for a content hash: the leading 16 hex
/// characters (64 bits) of the SHA-256, read as a big-endian `u64` and
/// reinterpreted as the `bigint` Postgres wants.
///
/// A `ContentHash` is validated 64-character lowercase hex at
/// construction, so the parse cannot fail on a well-formed value; a
/// malformed one would be a corrupt column, and it degrades to key `0`
/// rather than panicking on a path whose only job is to serialise two
/// writers.
///
/// **A key collision is safe.** Two hashes sharing a key serialise
/// against each other needlessly — the sweep sees `Contended` and comes
/// back next run — but neither side can act on the other's count: the
/// count is always re-read for the hash the caller named. Over 64 bits
/// of a cryptographic digest a collision is not reachable in practice
/// anyway.
pub(crate) fn blob_lock_key(hash: &ContentHash) -> i64 {
    let hex = hash.as_ref();
    let head = hex.get(..16).unwrap_or("");
    u64::from_str_radix(head, 16).unwrap_or(0) as i64
}

/// Take the blob lock for `hash`, **waiting** until it is free.
///
/// This is the reference-writer's side. It waits because the writer is
/// serving a request that must not fail over housekeeping, and the wait
/// is bounded by one storage `delete` — the only thing that holds this
/// lock for longer than a statement.
pub(crate) async fn lock_blob_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    hash: &ContentHash,
) -> DomainResult<()> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(blob_lock_key(hash))
        .execute(&mut **tx)
        .await
        .map_err(|e| map_sqlx_error(&e, "blob_lock", "acquire"))?;
    Ok(())
}

/// Try to take the blob lock for `hash`; `false` means another session
/// holds it.
///
/// This is the destructive side. It never waits: a sweep blocking on a
/// lock held by a live ingest would be housekeeping outranking a
/// request, and "someone else is touching these bytes right now" is
/// already the answer it needs.
pub(crate) async fn try_lock_blob_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    hash: &ContentHash,
) -> DomainResult<bool> {
    let taken: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(blob_lock_key(hash))
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| map_sqlx_error(&e, "blob_lock", "try_acquire"))?;
    Ok(taken)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn h(s: &str) -> ContentHash {
        ContentHash::from_str(s).expect("valid hash")
    }

    const HASH_A: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const HASH_B: &str = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    /// The key is the leading 64 bits, big-endian, sign-reinterpreted —
    /// pinned against a hand-computed value so a change to the
    /// derivation is a test failure rather than a silent re-keying that
    /// would leave an old process and a new one locking different keys
    /// for the same blob during a rolling upgrade.
    #[test]
    fn key_is_the_leading_64_bits_of_the_digest() {
        assert_eq!(blob_lock_key(&h(HASH_A)), 0xe3b0_c442_98fc_1c14_u64 as i64);
        assert_eq!(blob_lock_key(&h(HASH_B)), 0xb94d_27b9_934d_3e08_u64 as i64);
    }

    /// A leading bit set means a negative `bigint`; Postgres takes the
    /// full signed range, so this must not saturate or wrap oddly.
    #[test]
    fn a_high_bit_digest_keys_negative_and_round_trips() {
        let key = blob_lock_key(&h(HASH_B));
        assert!(key < 0, "0xb9… has the high bit set: {key}");
        assert_eq!(key as u64, 0xb94d_27b9_934d_3e08_u64);
    }

    /// Distinct digests key distinctly — the property the lock's
    /// per-blob granularity rests on.
    #[test]
    fn distinct_digests_key_distinctly() {
        assert_ne!(blob_lock_key(&h(HASH_A)), blob_lock_key(&h(HASH_B)));
    }
}
