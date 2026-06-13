//! Shared blob-streaming helper for the inbound-HTTP layer.
//!
//! Every per-format crate that serves artifact bytes (`hort-http-cargo`,
//! `hort-http-npm`, `hort-http-oci`, `hort-http-pypi`) wraps the CAS reader
//! returned by `StoragePort::get` / `get_range` into an axum [`Body`].
//! The naive `Body::from_stream(ReaderStream::new(stream))` uses
//! `tokio_util`'s 4 KB default buffer, which causes ~850 yield cycles
//! per request for a 3-4 MB blob — the byte-pump dominates wall-clock
//! latency at request granularity. Centralising the wiring here lets
//! the buffer size be picked once with bench evidence and varied per
//! call site if a format's typical artifact size warrants it.
//!
//! See ADR 0008 for the broader `hort-http-core` contract this module
//! participates in.

use axum::body::Body;
use tokio::io::AsyncRead;
use tokio_util::io::ReaderStream;

/// Default `ReaderStream` capacity for blob-serving handlers.
///
/// 64 KiB. Picked by bench on a 3.4 MB random tarball over loopback:
/// at this size the parallel (c=10) p50 drops ~22% vs the
/// `ReaderStream::new` default (4 KiB) and aggregate throughput rises
/// ~8%, with bounded p99 inflation. Larger values (256 KiB+) push
/// serial latency lower but inflate the tail under contention;
/// smaller values regress across the board. Format crates with
/// markedly different typical artifact sizes (very large OCI layers,
/// very small PyPI metadata siblings) may pass a different capacity.
pub const DEFAULT_STREAM_CAPACITY: usize = 64 * 1024;

/// Wrap an `AsyncRead` into an axum [`Body`] streamed in `capacity`-
/// sized chunks.
///
/// Use [`DEFAULT_STREAM_CAPACITY`] unless the format's artifact size
/// distribution makes a different choice provably better.
pub fn stream_blob<R>(reader: R, capacity: usize) -> Body
where
    R: AsyncRead + Send + Unpin + 'static,
{
    Body::from_stream(ReaderStream::with_capacity(reader, capacity))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::ReadBuf;

    /// Minimal owned `AsyncRead` for tests: yields the entire payload
    /// in successive `poll_read` calls, EOF when exhausted. Lives in
    /// the test module so `body.rs` adds no test-only deps.
    struct VecReader {
        data: Vec<u8>,
        pos: usize,
    }

    impl VecReader {
        fn new(data: Vec<u8>) -> Self {
            Self { data, pos: 0 }
        }
    }

    impl AsyncRead for VecReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let remaining = &self.data[self.pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.pos += n;
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn stream_blob_roundtrips_bytes_with_default_capacity() {
        // 192 KB — exceeds 64 KB default so the stream yields multiple
        // chunks; the helper must produce the exact byte sequence with
        // no boundary corruption.
        let payload: Vec<u8> = (0..192 * 1024).map(|i| (i % 251) as u8).collect();
        let body = stream_blob(VecReader::new(payload.clone()), DEFAULT_STREAM_CAPACITY);

        let collected = to_bytes(body, usize::MAX).await.expect("collect body");
        assert_eq!(collected.as_ref(), payload.as_slice());
    }

    #[tokio::test]
    async fn stream_blob_honours_small_capacity() {
        // Capacity smaller than the payload — exercises the multi-poll
        // path. The yielded bytes still match input.
        let payload = b"abcdefghijklmnopqrstuvwxyz0123456789".to_vec();
        let body = stream_blob(VecReader::new(payload.clone()), 8);

        let collected = to_bytes(body, usize::MAX).await.expect("collect body");
        assert_eq!(collected.as_ref(), payload.as_slice());
    }
}
