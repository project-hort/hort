//! Streaming integrity verification for CAS reads.
//!
//! `VerifyingReader` wraps an `AsyncRead` and accumulates a SHA-256 hasher
//! as bytes flow through. At EOF the computed hash is compared to the
//! expected `ContentHash` and the final `poll_read` yields an error on
//! mismatch (ADR 0003).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, ReadBuf};

use hort_domain::types::ContentHash;

/// Wraps an inner `AsyncRead`, hashes every byte that flows through, and
/// verifies the accumulated SHA-256 against `expected` at EOF (ADR 0003).
///
/// `on_mismatch` fires exactly once when (and only when) the computed hash
/// differs from `expected`. Used by adapters to emit
/// `hort_storage_integrity_failures_total`; kept as an injected callback so
/// the reader itself stays metric-agnostic and unit-testable without a
/// metrics runtime.
pub(crate) struct VerifyingReader<R> {
    inner: R,
    hasher: Sha256,
    expected: ContentHash,
    finalised: bool,
    on_mismatch: Option<Box<dyn FnOnce() + Send + Sync>>,
}

impl<R> VerifyingReader<R> {
    /// Construct a verifying reader. `on_mismatch` is called at most once
    /// when (and only when) the EOF-computed hash differs from `expected`;
    /// pass `None` to skip the side effect (unit tests without a metrics
    /// recorder).
    pub(crate) fn new(
        inner: R,
        expected: ContentHash,
        on_mismatch: Option<Box<dyn FnOnce() + Send + Sync>>,
    ) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            expected,
            finalised: false,
            on_mismatch,
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for VerifyingReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let new_bytes = &buf.filled()[before..];
                if new_bytes.is_empty() {
                    // EOF — verify.
                    if !self.finalised {
                        self.finalised = true;
                        let computed_hex = format!("{:x}", self.hasher.clone().finalize());
                        // SHA-256 always produces 64 lowercase hex chars — the
                        // `ContentHash::from_str` parse is guaranteed to succeed.
                        let computed: ContentHash = computed_hex
                            .parse()
                            .expect("SHA-256 digest is always valid ContentHash hex");
                        if computed != self.expected {
                            if let Some(cb) = self.on_mismatch.take() {
                                cb();
                            }
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!(
                                    "CAS integrity failure: expected {}, computed {}",
                                    self.expected, computed
                                ),
                            )));
                        }
                    }
                } else {
                    self.hasher.update(new_bytes);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io::Cursor;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

    use super::*;

    /// SHA-256 of b"hello world".
    const HELLO_WORLD_SHA256: &str =
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
    /// SHA-256 of the empty byte string.
    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn hash(hex: &str) -> ContentHash {
        hex.parse().unwrap()
    }

    /// Reader whose bytes hash to the declared `expected` — read-to-end
    /// delivers the original bytes and yields no error. Baseline.
    #[tokio::test]
    async fn happy_path_passes_bytes_through_and_verifies_at_eof() {
        let inner = Cursor::new(b"hello world".to_vec());
        let mut reader = VerifyingReader::new(inner, hash(HELLO_WORLD_SHA256), None);

        let mut out = Vec::new();
        reader.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"hello world");
    }

    /// Multi-chunk read: a reader that delivers bytes across many small
    /// `poll_read` calls must still verify correctly at EOF. Guards the
    /// `before = buf.filled().len()` incremental-hashing logic against
    /// regressions that would accumulate on already-hashed bytes or miss
    /// bytes delivered by later polls.
    #[tokio::test]
    async fn multi_chunk_read_verifies_correctly() {
        // ChunkedReader yields one byte at a time, exercising poll_read
        // many times and verifying the incremental accumulation.
        struct ChunkedReader(VecDeque<u8>);
        impl AsyncRead for ChunkedReader {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                if let Some(b) = self.0.pop_front() {
                    buf.put_slice(&[b]);
                }
                Poll::Ready(Ok(()))
            }
        }

        let data: Vec<u8> = b"hello world".to_vec();
        let inner = ChunkedReader(data.clone().into());
        let mut reader = VerifyingReader::new(inner, hash(HELLO_WORLD_SHA256), None);

        let mut out = Vec::new();
        reader.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, data);
    }

    /// Multi-chunk + mismatch: proves verification happens even when the
    /// inner reader delivers bytes across many polls. This is the stronger
    /// regression guard — a bug that made `poll_read` hash the cumulative
    /// `buf.filled()` (instead of only the newly-filled slice) would cause
    /// the EOF-verify branch to never fire under `read_to_end`'s
    /// growing-buffer usage, and this test catches that.
    #[tokio::test]
    async fn multi_chunk_mismatch_still_errors_at_eof() {
        struct ChunkedReader(VecDeque<u8>);
        impl AsyncRead for ChunkedReader {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                if let Some(b) = self.0.pop_front() {
                    buf.put_slice(&[b]);
                }
                Poll::Ready(Ok(()))
            }
        }

        let inner = ChunkedReader(b"hello world".to_vec().into());
        // Wrong hash: wants empty, bytes hash to HELLO_WORLD_SHA256.
        let mut reader = VerifyingReader::new(inner, hash(EMPTY_SHA256), None);

        let mut out = Vec::new();
        let err = reader.read_to_end(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// Empty content with the empty-SHA-256 expected — the reader must
    /// pass through cleanly. Guards against an implementation that only
    /// runs the finalise branch after some non-empty poll.
    #[tokio::test]
    async fn empty_content_with_empty_hash_verifies_clean() {
        let inner = Cursor::new(Vec::<u8>::new());
        let mut reader = VerifyingReader::new(inner, hash(EMPTY_SHA256), None);

        let mut out = Vec::new();
        reader.read_to_end(&mut out).await.unwrap();
        assert!(out.is_empty());
    }

    /// Empty content with a non-empty expected hash must error. Paired
    /// with the above — together they prove the finalise branch fires
    /// at least once regardless of payload.
    #[tokio::test]
    async fn empty_content_with_wrong_hash_errors() {
        let inner = Cursor::new(Vec::<u8>::new());
        let mut reader = VerifyingReader::new(inner, hash(HELLO_WORLD_SHA256), None);

        let mut out = Vec::new();
        let err = reader.read_to_end(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// The `on_mismatch` callback fires exactly once when the hash
    /// doesn't match. Guards against a refactor that double-fires (e.g.
    /// on every EOF poll after the first) or that fires on success.
    #[tokio::test]
    async fn on_mismatch_callback_fires_once_on_mismatch() {
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_clone = Arc::clone(&hits);

        let inner = Cursor::new(b"hello world".to_vec());
        let mut reader = VerifyingReader::new(
            inner,
            hash(EMPTY_SHA256), // wrong
            Some(Box::new(move || {
                hits_clone.fetch_add(1, Ordering::SeqCst);
            })),
        );

        let mut out = Vec::new();
        let _ = reader.read_to_end(&mut out).await;
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    /// The `on_mismatch` callback MUST NOT fire on a successful match.
    #[tokio::test]
    async fn on_mismatch_callback_does_not_fire_on_match() {
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_clone = Arc::clone(&hits);

        let inner = Cursor::new(b"hello world".to_vec());
        let mut reader = VerifyingReader::new(
            inner,
            hash(HELLO_WORLD_SHA256), // correct
            Some(Box::new(move || {
                hits_clone.fetch_add(1, Ordering::SeqCst);
            })),
        );

        let mut out = Vec::new();
        reader.read_to_end(&mut out).await.unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    /// Reader whose bytes don't hash to the declared `expected` — must
    /// yield `io::ErrorKind::InvalidData` at EOF. The error message must
    /// name both the expected and the computed hash so ops can diagnose.
    #[tokio::test]
    async fn mismatch_yields_invalid_data_at_eof() {
        // Bytes hash to HELLO_WORLD_SHA256, but we declare EMPTY_SHA256.
        let inner = Cursor::new(b"hello world".to_vec());
        let mut reader = VerifyingReader::new(inner, hash(EMPTY_SHA256), None);

        let mut out = Vec::new();
        let err = reader.read_to_end(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let msg = err.to_string();
        assert!(
            msg.contains(EMPTY_SHA256),
            "error should name expected hash, got: {msg}"
        );
        assert!(
            msg.contains(HELLO_WORLD_SHA256),
            "error should name computed hash, got: {msg}"
        );
    }
}
