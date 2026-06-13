//! Streaming SHA-512 hasher for the npm SRI verification path
//! (mandatory upstream verification, ADR 0006).
//!
//! `Sha512HashingRead` wraps any `AsyncRead` and feeds bytes through a
//! SHA-512 hasher as they pass. The wrapped stream is what the storage
//! adapter sees; on completion the use case calls `finalize()` and
//! compares the result to the upstream-published hex.
//!
//! The wrapper is generic in shape but specialised in code — only npm
//! needs SHA-512 today. When a future format introduces SHA-3 / BLAKE3,
//! add a sibling type rather than abstracting prematurely.
//!
//! ## Why a digest handle
//!
//! The ingest pipeline boxes the wrapper into `Box<dyn AsyncRead + Send +
//! Unpin>` and hands it to `StoragePort::put`, which consumes the box.
//! After `put` returns the SHA-256 CAS hash, the use case still needs
//! the SHA-512 digest to compare against the upstream-published value —
//! but the wrapper is gone. The hasher state is therefore held inside an
//! `Arc<Mutex<Sha512>>`; calling [`Sha512HashingRead::digest_handle`]
//! before boxing returns a [`Sha512DigestHandle`] whose
//! [`Sha512DigestHandle::finalize`] reads the state once the boxed
//! stream has been drained.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use sha2::{Digest, Sha512};
use tokio::io::{AsyncRead, ReadBuf};

/// AsyncRead wrapper that incrementally hashes bytes as they pass
/// through. Hashing is "free" — the same chunk that the inner reader
/// produced is fed verbatim into the hasher; no buffering, no extra
/// allocation.
pub struct Sha512HashingRead<R> {
    inner: R,
    hasher: Arc<Mutex<Sha512>>,
}

impl<R> Sha512HashingRead<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Arc::new(Mutex::new(Sha512::new())),
        }
    }

    /// Return a clone-able handle that finalises the SHA-512 digest of
    /// bytes that flow through this wrapper. Used when the wrapper has
    /// to be boxed (e.g. handed to `StoragePort::put`) and the caller
    /// still needs the digest after the box has been consumed —
    /// [`Self::finalize`] is unreachable in that shape.
    ///
    /// Multiple handles may be obtained; they all observe the same
    /// hasher state. Calling [`Sha512DigestHandle::finalize`] swaps the
    /// hasher with a fresh one, so a second `finalize` (on this or any
    /// sibling handle) sees the digest of bytes hashed since the
    /// previous swap. Callers that need a one-shot digest should call
    /// `finalize` once and not reuse the handle.
    pub fn digest_handle(&self) -> Sha512DigestHandle {
        Sha512DigestHandle {
            hasher: self.hasher.clone(),
        }
    }

    /// Consume the wrapper and return the SHA-512 digest of every byte
    /// that flowed through `poll_read`. Equivalent to
    /// `digest_handle().finalize()` but does not require obtaining a
    /// separate handle. Available only when the wrapper has not been
    /// boxed; for the boxed case use [`Self::digest_handle`].
    pub fn finalize(self) -> [u8; 64] {
        let mut guard = self
            .hasher
            .lock()
            .expect("Sha512HashingRead hasher poisoned");
        let taken = std::mem::replace(&mut *guard, Sha512::new());
        taken.finalize().into()
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for Sha512HashingRead<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let pre = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        let post = buf.filled().len();
        // Hash only the net-new bytes — `poll_read` MAY be called
        // multiple times before the buffer fills, and the inner reader
        // MAY produce 0 bytes on a spurious wake. Hashing the whole
        // `buf.filled()` would either re-hash earlier chunks or hash
        // already-stale bytes after a partial read.
        if post > pre {
            let mut guard = self
                .hasher
                .lock()
                .expect("Sha512HashingRead hasher poisoned");
            guard.update(&buf.filled()[pre..post]);
        }
        res
    }
}

/// Out-of-band handle to the SHA-512 hasher state of a
/// [`Sha512HashingRead`]. Constructed via
/// [`Sha512HashingRead::digest_handle`]; `finalize` reads the digest of
/// bytes that flowed through the wrapper up to the call.
///
/// `Clone` is supported so the handle can be split across the
/// pre-`storage.put` and post-`storage.put` halves of a verification
/// pipeline without extra plumbing.
#[derive(Clone)]
pub struct Sha512DigestHandle {
    hasher: Arc<Mutex<Sha512>>,
}

impl Sha512DigestHandle {
    /// Read the SHA-512 digest of bytes hashed so far and reset the
    /// shared hasher to a fresh state. The reset is required so the
    /// `Sha512` value can be moved out by-value into `finalize()`;
    /// callers that need a one-shot digest call this once.
    pub fn finalize(&self) -> [u8; 64] {
        let mut guard = self
            .hasher
            .lock()
            .expect("Sha512HashingRead hasher poisoned");
        let taken = std::mem::replace(&mut *guard, Sha512::new());
        taken.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    /// SHA-512 of the empty string — NIST FIPS 180-4 test vector.
    const SHA512_EMPTY: [u8; 64] = [
        0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80,
        0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c,
        0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83, 0x18, 0xd2, 0x87,
        0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a,
        0xf9, 0x27, 0xda, 0x3e,
    ];

    /// SHA-512 of "abc" — NIST FIPS 180-4 test vector.
    const SHA512_ABC: [u8; 64] = [
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41,
        0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55,
        0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3,
        0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f,
        0xa5, 0x4c, 0xa4, 0x9f,
    ];

    #[tokio::test]
    async fn empty_stream_produces_sha512_of_empty() {
        let inner = tokio::io::empty();
        let mut wrapper = Sha512HashingRead::new(inner);
        let mut sink = Vec::new();
        wrapper.read_to_end(&mut sink).await.unwrap();
        assert_eq!(sink.len(), 0);
        assert_eq!(wrapper.finalize(), SHA512_EMPTY);
    }

    #[tokio::test]
    async fn abc_stream_produces_sha512_of_abc() {
        let inner = std::io::Cursor::new(b"abc".to_vec());
        let mut wrapper = Sha512HashingRead::new(inner);
        let mut sink = Vec::new();
        wrapper.read_to_end(&mut sink).await.unwrap();
        assert_eq!(sink, b"abc");
        assert_eq!(wrapper.finalize(), SHA512_ABC);
    }

    #[tokio::test]
    async fn long_stream_hashes_correctly_across_partial_reads() {
        // 10 MB of zeros — the inner Cursor's poll_read may yield
        // multiple chunks. The SHA-512 of 10 MB of `0x00` is fixed and
        // verifiable independently (sha512sum < /dev/zero piped).
        let inner = std::io::Cursor::new(vec![0u8; 10 * 1024 * 1024]);
        let mut wrapper = Sha512HashingRead::new(inner);
        let mut sink = Vec::new();
        wrapper.read_to_end(&mut sink).await.unwrap();
        assert_eq!(sink.len(), 10 * 1024 * 1024);
        // Compute the same digest with a fresh hasher to verify
        // the wrapper agrees with the canonical SHA-512.
        let mut reference = Sha512::new();
        reference.update(vec![0u8; 10 * 1024 * 1024]);
        let canonical: [u8; 64] = reference.finalize().into();
        assert_eq!(wrapper.finalize(), canonical);
    }

    #[tokio::test]
    async fn small_chunked_reads_hash_correctly() {
        // Force many tiny reads via a small destination buffer. Each
        // call goes through `poll_read` separately; if the wrapper
        // double-hashed or missed the boundary bytes, the final digest
        // would diverge from the canonical "abc" reference.
        let inner = std::io::Cursor::new(b"abc".to_vec());
        let mut wrapper = Sha512HashingRead::new(inner);
        let mut sink = [0u8; 1];
        wrapper.read_exact(&mut sink).await.unwrap();
        assert_eq!(&sink, b"a");
        wrapper.read_exact(&mut sink).await.unwrap();
        assert_eq!(&sink, b"b");
        wrapper.read_exact(&mut sink).await.unwrap();
        assert_eq!(&sink, b"c");
        assert_eq!(wrapper.finalize(), SHA512_ABC);
    }

    /// `digest_handle` lets the caller read the SHA-512 after the
    /// wrapper has been consumed by being boxed into a
    /// `Box<dyn AsyncRead>` — the shape `StoragePort::put` requires.
    /// Without this path the SHA-512 value would be unrecoverable on
    /// the npm pull-through path.
    #[tokio::test]
    async fn digest_handle_reads_after_boxed_consumption() {
        let inner = std::io::Cursor::new(b"abc".to_vec());
        let wrapper = Sha512HashingRead::new(inner);
        let handle = wrapper.digest_handle();

        // Box the wrapper — the boxed stream owns the wrapper. Drain it
        // via the trait-object surface, just like `StoragePort::put`.
        let mut boxed: Box<dyn AsyncRead + Send + Unpin> = Box::new(wrapper);
        let mut sink = Vec::new();
        boxed.read_to_end(&mut sink).await.unwrap();
        assert_eq!(sink, b"abc");

        // Drop the box so the wrapper is gone. The digest is still
        // readable through the handle.
        drop(boxed);
        assert_eq!(handle.finalize(), SHA512_ABC);
    }

    /// The handle can be cloned; both clones observe the same hasher
    /// state. After one clone calls `finalize` (which resets the
    /// hasher), a sibling clone observes the post-reset state — which
    /// for a freshly-reset hasher is the digest of the empty input.
    /// Documents the reset semantics explicitly so a future caller does
    /// not silently double-finalize.
    #[tokio::test]
    async fn digest_handle_finalize_resets_shared_state() {
        let inner = std::io::Cursor::new(b"abc".to_vec());
        let wrapper = Sha512HashingRead::new(inner);
        let h1 = wrapper.digest_handle();
        let h2 = h1.clone();

        let mut boxed: Box<dyn AsyncRead + Send + Unpin> = Box::new(wrapper);
        let mut sink = Vec::new();
        boxed.read_to_end(&mut sink).await.unwrap();

        assert_eq!(h1.finalize(), SHA512_ABC);
        // After h1.finalize() the shared hasher was swapped for a
        // fresh one — h2 now observes the empty digest.
        assert_eq!(h2.finalize(), SHA512_EMPTY);
    }

    /// `finalize` on a wrapper that produced a handle and then was
    /// boxed-and-dropped must agree with what the handle observes — the
    /// state is shared, not duplicated.
    #[tokio::test]
    async fn finalize_consuming_path_agrees_with_handle() {
        let inner = std::io::Cursor::new(b"abc".to_vec());
        let wrapper = Sha512HashingRead::new(inner);
        let handle = wrapper.digest_handle();
        // Read via the wrapper directly (no boxing); both finalize
        // paths must yield the canonical "abc" digest.
        let mut wrapper = wrapper;
        let mut sink = Vec::new();
        wrapper.read_to_end(&mut sink).await.unwrap();
        let digest_via_wrapper = wrapper.finalize();
        assert_eq!(digest_via_wrapper, SHA512_ABC);
        // Wrapper consumed; the handle observes the (now-reset) state.
        assert_eq!(handle.finalize(), SHA512_EMPTY);
    }
}
