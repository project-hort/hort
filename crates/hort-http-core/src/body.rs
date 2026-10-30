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
//! The wiring also carries the integrity close described on
//! [`HoldBackFinalChunk`]: a CAS read's verdict arrives *after* the last
//! byte, so the last chunk is withheld until the stream has ended
//! cleanly.
//!
//! See ADR 0008 for the broader `hort-http-core` contract this module
//! participates in.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::Body;
use bytes::Bytes;
use futures::Stream;
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

/// Delays a byte stream by one item: chunk *i* is yielded only once the
/// inner stream has produced chunk *i+1* or ended cleanly. When the inner
/// stream ends with an error instead, the withheld chunk is **dropped**
/// and the error is yielded in its place.
///
/// ## Why a response body needs this
///
/// A CAS read verifies at EOF — it can only know the digest once it has
/// seen every byte — so `StoragePort::get`'s reader raises its verdict
/// *after* the last byte has already been handed upwards. Every
/// blob-serving handler announces `Content-Length: N`, which makes a
/// response of fewer than N octets detectable but a response of exactly N
/// octets complete. So a **same-length** substitution — N different bytes
/// in place of the N stored ones — satisfies the framing, and the error
/// that follows has no field left to arrive in: HTTP/1 has no late-error
/// channel for a length-delimited body. The substitution was detected
/// (the metric fires, `CasScrubUseCase` gets its finding) by everyone
/// except the party now holding the wrong bytes.
///
/// Withholding the final chunk converts that into the one failure HTTP/1
/// does signal. On a verdict the client has fewer octets than the
/// `Content-Length` it was promised and the connection closes, which
/// every HTTP/1 client reports as an incomplete transfer; on a clean end
/// the chunk goes out and the response is byte-identical to before.
///
/// ## What it costs
///
/// One inner read of latency at the end of the body — the chunk flushes
/// after the read that reports EOF, rather than concurrently with it —
/// and at most `capacity` bytes held in memory, which is the buffer
/// `ReaderStream` already allocates. Nothing accumulates: the payload is
/// never materialised, so ADR 0003's streaming guarantee is untouched. A
/// blob smaller than one chunk is withheld in its entirety, which is the
/// same bound.
///
/// Applied to every `stream_blob` caller rather than only the verified
/// ones. Unverified reads (`StoragePort::get_range`, which cannot verify
/// — a partial digest never matches the whole-content hash) pay the
/// trailing read and gain nothing, and that is the cheaper half of the
/// trade: picking per call site is the convention this codebase has
/// repeatedly watched not hold, and a new format crate cannot forget a
/// hold-back it does not have to ask for.
struct HoldBackFinalChunk<S> {
    inner: S,
    /// The chunk not yet handed on. `None` before the first chunk and
    /// after the stream has terminated.
    withheld: Option<Bytes>,
    /// Set once the inner stream has ended (either way), so a consumer
    /// that polls again gets `None` rather than touching the inner
    /// stream after completion.
    ended: bool,
}

impl<S> HoldBackFinalChunk<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            withheld: None,
            ended: false,
        }
    }
}

impl<S> Stream for HoldBackFinalChunk<S>
where
    S: Stream<Item = io::Result<Bytes>> + Unpin,
{
    type Item = io::Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            if this.ended {
                return Poll::Ready(None);
            }
            match Pin::new(&mut this.inner).poll_next(cx) {
                // A chunk arrives: it takes the withheld slot, and the
                // chunk it displaces is now known to be followed by more
                // bytes, so it is safe to hand on. The first chunk
                // displaces nothing, hence the loop.
                Poll::Ready(Some(Ok(chunk))) => {
                    if let Some(ready) = this.withheld.replace(chunk) {
                        return Poll::Ready(Some(Ok(ready)));
                    }
                }
                // The verdict. Dropping the withheld chunk here is the
                // whole point: the client is left short of the announced
                // `Content-Length`.
                Poll::Ready(Some(Err(error))) => {
                    this.ended = true;
                    this.withheld = None;
                    return Poll::Ready(Some(Err(error)));
                }
                // Clean end — the verifier was satisfied, so the last
                // chunk goes out.
                Poll::Ready(None) => {
                    this.ended = true;
                    return Poll::Ready(this.withheld.take().map(Ok));
                }
                // Not ready: keep withholding. The chunk is held across
                // the wakeup rather than flushed early, which is what
                // makes the delay hold for a slow backend too.
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// Wrap an `AsyncRead` into an axum [`Body`] streamed in `capacity`-
/// sized chunks, with the final chunk withheld until the read has ended
/// cleanly ([`HoldBackFinalChunk`]).
///
/// Use [`DEFAULT_STREAM_CAPACITY`] unless the format's artifact size
/// distribution makes a different choice provably better.
pub fn stream_blob<R>(reader: R, capacity: usize) -> Body
where
    R: AsyncRead + Send + Unpin + 'static,
{
    Body::from_stream(HoldBackFinalChunk::new(ReaderStream::with_capacity(
        reader, capacity,
    )))
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
        ) -> Poll<io::Result<()>> {
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

    /// An error from the inner reader must reach the body consumer —
    /// the hold-back delays data, it must never swallow a verdict.
    #[tokio::test]
    async fn stream_blob_propagates_a_trailing_reader_error() {
        /// Yields `payload`, then errors at EOF — the
        /// `VerifyingReader` same-length-substitution shape.
        struct FailAtEof {
            payload: Vec<u8>,
            pos: usize,
        }

        impl AsyncRead for FailAtEof {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                if self.pos == self.payload.len() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "integrity",
                    )));
                }
                let n = (self.payload.len() - self.pos).min(buf.remaining());
                let from = self.pos;
                buf.put_slice(&self.payload[from..from + n]);
                self.pos += n;
                Poll::Ready(Ok(()))
            }
        }

        let body = stream_blob(
            FailAtEof {
                payload: vec![7u8; 4],
                pos: 0,
            },
            2,
        );
        let err = to_bytes(body, usize::MAX)
            .await
            .expect_err("the trailing error must surface");
        assert!(err.to_string().contains("integrity"), "got: {err}");
    }

    /// The withheld chunk is dropped rather than flushed when the stream
    /// errors, so a consumer that collects the body sees strictly fewer
    /// bytes than were read out of the backend. This is the property the
    /// `Content-Length` framing turns into a client-visible incomplete
    /// transfer; asserted here on the stream itself so a regression is
    /// localised even if the HTTP-level test is the one that fails.
    #[tokio::test]
    async fn hold_back_drops_the_withheld_chunk_on_error() {
        let chunks: Vec<Result<Bytes, io::Error>> = vec![
            Ok(Bytes::from_static(b"aaa")),
            Ok(Bytes::from_static(b"bbb")),
            Err(io::Error::other("verdict")),
        ];
        let mut held = HoldBackFinalChunk::new(futures::stream::iter(chunks));

        let mut delivered = Vec::new();
        let mut error = None;
        while let Some(item) = futures::StreamExt::next(&mut held).await {
            match item {
                Ok(chunk) => delivered.extend_from_slice(&chunk),
                Err(e) => {
                    error = Some(e);
                    break;
                }
            }
        }
        assert_eq!(
            delivered, b"aaa",
            "only the chunk the next one displaced may be delivered"
        );
        assert!(error.is_some(), "the verdict must be yielded");
        assert!(
            futures::StreamExt::next(&mut held).await.is_none(),
            "the stream is finished after the verdict"
        );
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
