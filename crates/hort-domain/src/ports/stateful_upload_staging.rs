//! Stateful-upload staging port.
//!
//! Staging is the scratch-space side of any three-phase / chunked
//! stateful upload (OCI blob upload, Maven chunked PUT, Git LFS batch
//! transfer, …). It holds the raw bytes accumulated from PATCH / PUT
//! chunks, addressed by the caller-supplied session UUID (not by
//! content hash — the final SHA-256 is not known until finalize). On
//! finalize the use case streams staging through `StoragePort::put`
//! (which hashes + writes to CAS) and calls
//! [`StatefulUploadStagingPort::delete`] to clean up.
//!
//! # Format-agnostic
//!
//! The port has no OCI-specific contract. It is a bytes-on-disk
//! primitive shared by every format that needs a pre-finalization
//! staging area. Callers namespace session UUIDs themselves (the OCI
//! path uses the upload session UUID; Maven / LFS items will namespace
//! differently). Adapters MUST NOT interpret session UUIDs beyond
//! converting them to a filesystem-safe filename.
//!
//! # Distinct from `StoragePort`
//!
//! The two ports are deliberately separate:
//!
//! - `StoragePort` is content-addressable. Callers never supply keys;
//!   the hash is derived from the bytes as they stream through `put`.
//! - `StatefulUploadStagingPort` is session-addressable. Keys are the
//!   upload session UUID. Chunks accumulate before the content hash
//!   exists; CAS cannot represent that state.
//!
//! Adapters MUST own separate directory trees and MUST NOT share CAS
//! code paths. Staging bytes are pre-finalization and may never land in
//! CAS (client aborts the upload, digest mismatch on finalize, GC
//! sweep of expired sessions).

use tokio::io::AsyncRead;
use uuid::Uuid;

use crate::error::DomainResult;

use super::BoxFuture;

/// Outcome of one [`StatefulUploadStagingPort::append_at`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StagingAppend {
    /// The staging file's physical length after the write — always
    /// `offset + <bytes written>`, because the write is positioned at
    /// `offset` and the adapter drops anything that was beyond it.
    pub total: u64,
    /// `stream` still had bytes when the `limit` was reached. The
    /// surplus was **not** written: the over-limit signal lives here,
    /// never in the file's length. A caller that cannot distinguish "the
    /// body exactly filled the budget" (legal) from "the body wanted
    /// more than the budget" (reject) has to encode that bit somewhere,
    /// and encoding it by letting one surplus byte land on disk makes
    /// the file exceed the very cap the budget expresses.
    pub truncated: bool,
}

/// Scratch-space port for chunks-in-flight during three-phase / chunked
/// stateful upload.
///
/// Distinct from [`StoragePort`](crate::ports::storage::StoragePort)
/// (CAS) by design: chunks are not content-addressable until the final
/// digest is known. Adapters stage under the session UUID; on finalize,
/// the use case streams staging through `StoragePort::put` (which
/// computes the real hash) and calls [`delete`](Self::delete) here to
/// clean up.
pub trait StatefulUploadStagingPort: Send + Sync {
    /// Write up to `limit` bytes from `stream` into the staging area for
    /// `session_id`, **starting at `offset`**. Creates the staging file
    /// on first call.
    ///
    /// # Position is asserted, not discovered
    ///
    /// `offset` is the caller's recorded progress for the session. The
    /// adapter writes there rather than at whatever the file's current
    /// end happens to be, which is what keeps the physical file from
    /// ever becoming the authority on how much of the upload has landed:
    ///
    /// - `offset == len(file)` — the ordinary case. The bytes extend the
    ///   file and `total` is `offset + n`.
    /// - `offset > len(file)` — a gap. The adapter writes **nothing**
    ///   and returns [`DomainError::Invariant`](crate::error::DomainError::Invariant):
    ///   filling the hole would put bytes the client never sent into the
    ///   middle of the content, and the finalize-time digest check would
    ///   then reject a blob whose body the registry itself corrupted.
    /// - `offset < len(file)` — bytes past the caller's recorded
    ///   progress, i.e. debris from an earlier write whose record update
    ///   never landed. The adapter truncates to `offset` before writing.
    ///   That is a repair, not data loss: the caller's record is the
    ///   authority and does not account for those bytes, so no finalize
    ///   can ever turn them into content.
    ///
    /// At most `limit` bytes are written. If `stream` has more,
    /// [`StagingAppend::truncated`] is set and the surplus is discarded,
    /// so the file's length never exceeds `offset + limit`.
    ///
    /// # Concurrency contract
    ///
    /// The port does **not** resolve concurrent writers and callers must
    /// not lean on it to. Two `append_at` calls racing on one
    /// `session_id` aim at the same `offset`, so the loser overwrites the
    /// winner's bytes rather than extending past them.
    ///
    /// **Callers MUST serialise `append_at` per session by claiming the
    /// byte range in their own session record BEFORE calling here.** The
    /// OCI use case advances the session record's `bytes_received` to
    /// `offset + limit` through
    /// [`EphemeralStore::compare_and_swap`](crate::ports::ephemeral_store::EphemeralStore::compare_and_swap)
    /// *first*, so the loser of a `PATCH` race is rejected having written
    /// nothing at all. Claiming the range **after** the write serialises
    /// nothing: both racers reach the port, both write, and the file ends
    /// up longer than either record claims — which then makes every
    /// subsequent cap check compute against a length that is already
    /// stale, and the file grows once more on each retry.
    ///
    /// What position-checked writing buys even where a caller gets that
    /// ordering wrong: the file is bounded by `offset + limit` instead of
    /// growing by the sum of the racers' lengths. That is a backstop, not
    /// a substitute for the claim.
    fn append_at(
        &self,
        session_id: Uuid,
        offset: u64,
        limit: u64,
        stream: Box<dyn AsyncRead + Send + Unpin>,
    ) -> BoxFuture<'_, DomainResult<StagingAppend>>;

    /// Open the staging file for `session_id` for reading.
    ///
    /// Returns an `AsyncRead` positioned at the start of the file.
    /// Missing → `DomainError::NotFound { entity: "stateful_upload_staging", .. }`.
    /// Used on finalize to stream staging bytes through
    /// `StoragePort::put` for hashing.
    fn stream_read(
        &self,
        session_id: Uuid,
    ) -> BoxFuture<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>>;

    /// Remove the staging file for `session_id`.
    ///
    /// Idempotent — a missing file returns `Ok(())`. Finalize and GC
    /// races (both racing to delete the same session) are therefore
    /// benign.
    fn delete(&self, session_id: Uuid) -> BoxFuture<'_, DomainResult<()>>;

    /// List up to `max` staging session IDs currently held by the adapter.
    ///
    /// Bounded iteration — adapters MUST cap at `max` even if more entries
    /// exist. Ordering is unspecified; the sweep does not require deterministic
    /// ordering. Used by the staging-orphan sweep to enumerate sessions whose
    /// ephemeral key may have TTL'd out.
    fn list(&self, max: usize) -> BoxFuture<'_, DomainResult<Vec<Uuid>>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time assertion that `StatefulUploadStagingPort` is
    /// dyn-compatible — adapters are held as
    /// `Arc<dyn StatefulUploadStagingPort>` at composition.
    #[test]
    fn port_is_dyn_compatible() {
        let _ = size_of::<&dyn StatefulUploadStagingPort>();
    }
}
