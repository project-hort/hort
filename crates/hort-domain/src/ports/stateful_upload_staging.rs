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
    /// Append bytes from `stream` to the staging area for `session_id`.
    ///
    /// Reads `stream` to EOF, appends to the session's staging file,
    /// and returns the new total byte count for the session (i.e. the
    /// file's length after the flush). Creates the staging file on
    /// first call.
    ///
    /// # Concurrency contract
    ///
    /// Filesystem adapters are expected to use `O_APPEND` open-mode
    /// semantics, which the kernel serialises atomically for writes up
    /// to `PIPE_BUF` (4 KiB on Linux). Two concurrent `append` calls on
    /// the same `session_id` therefore produce a well-defined final
    /// byte-count equal to the sum of both stream lengths; the relative
    /// order of the two payloads in the file is unspecified but the
    /// content of each individual small write is not interleaved.
    ///
    /// Callers that require a strict ordering of chunks must serialise
    /// at a higher layer — the OCI use case does this by gating every
    /// `PATCH` on an optimistic-concurrency check against the upload
    /// session state held in
    /// [`EphemeralStore`](crate::ports::ephemeral_store::EphemeralStore)
    /// via `compare_and_swap`.
    fn append(
        &self,
        session_id: Uuid,
        stream: Box<dyn AsyncRead + Send + Unpin>,
    ) -> BoxFuture<'_, DomainResult<u64>>;

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
