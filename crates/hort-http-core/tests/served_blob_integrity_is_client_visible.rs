//! A CAS integrity failure must be visible **to the client**, not only to
//! the server's metrics.
//!
//! ## The invariant
//!
//! `StoragePort::get` returns a reader that accumulates SHA-256 as bytes
//! flow and raises the verdict at EOF — after the last byte. The serving
//! path wraps that reader in [`stream_blob`] and announces
//! `Content-Length: N` (every blob-serving handler does; the header is
//! load-bearing because without it axum chunk-encodes and a mid-stream
//! error can terminate as a *normal* chunked end).
//!
//! That combination has a gap that the length framing does not cover. A
//! **same-length** substitution — the blob's bytes replaced by exactly as
//! many different bytes — delivers all N announced bytes, so the message
//! is complete from the recipient's point of view *before* the verifier
//! has a verdict, and HTTP/1 has no late-error channel for a
//! length-delimited body. The read is detected (the metric fires, the
//! scrub gets its finding) by everyone except the one party that now
//! holds the wrong bytes.
//!
//! The close is to hold the final chunk back until the stream has ended
//! cleanly. On failure the client is left short of its announced length,
//! which is the one signal HTTP/1 does carry.
//!
//! ## Why the test is here and not on the reader
//!
//! A test against `VerifyingReader` alone proves nothing about this: the
//! reader already does its job, and did so before the fix. The claim is
//! about the bytes on the wire, so the assertion has to be made there —
//! over a real socket, counting the body octets a client actually
//! receives against the `Content-Length` it was promised. An
//! `oneshot`-style assertion that the body future resolves to `Err` would
//! pass on the broken code too, because the body did error — just too
//! late to matter.
//!
//! ## The premise, and where it is pinned
//!
//! The reader double here delivers all N bytes and then yields an
//! `io::Error` carrying a `CasIntegrityFailure` — which is exactly the
//! production reader's documented behaviour for a same-length
//! substitution, pinned by
//! `hort-adapters-storage`'s
//! `same_length_substitution_delivers_every_byte_then_errors`. The two
//! halves compose: that test fixes what the port hands the HTTP layer,
//! this one fixes what the HTTP layer hands the client.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use hort_domain::ports::storage::CasIntegrityFailure;
use hort_http_core::body::{stream_blob, DEFAULT_STREAM_CAPACITY};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

/// How the reader under the response terminates.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ending {
    /// Clean EOF — the verifier was satisfied.
    Eof,
    /// All bytes delivered, then the integrity verdict. The
    /// same-length-substitution shape.
    IntegrityFailureAtEof,
}

/// Delivers `data` in `chunk` -sized pieces, then ends per [`Ending`].
///
/// Chunked on purpose: a single-poll reader would make the whole body one
/// stream item and hide whether the hold-back is per chunk or per body.
///
/// Yields `Pending` (waking immediately) between pieces, because a reader
/// that is *never* `Pending` is not a backend — a file or an object-store
/// stream parks on I/O, and hyper flushes what it has when the body
/// parks. Without the yield hyper drains this whole body into its write
/// buffer before the first flush, so the trailing error discards the head
/// as well and the client observes a bare connection reset. That is
/// still a failed download, but it proves nothing about the length
/// framing, which is the claim under test.
struct ScriptedReader {
    data: Vec<u8>,
    pos: usize,
    chunk: usize,
    ending: Ending,
    /// Park on the next poll, so the consumer gets a chance to flush.
    park: bool,
}

impl AsyncRead for ScriptedReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.park {
            self.park = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        if self.pos == self.data.len() {
            return match self.ending {
                Ending::Eof => Poll::Ready(Ok(())),
                Ending::IntegrityFailureAtEof => Poll::Ready(Err(CasIntegrityFailure {
                    expected: "a".repeat(64).parse().expect("64 hex chars"),
                    computed: "b".repeat(64).parse().expect("64 hex chars"),
                }
                .into_io_error())),
            };
        }
        let want = self
            .chunk
            .min(buf.remaining())
            .min(self.data.len() - self.pos);
        let from = self.pos;
        buf.put_slice(&self.data[from..from + want]);
        self.pos += want;
        self.park = true;
        Poll::Ready(Ok(()))
    }
}

/// What a client observed on the wire.
struct Observed {
    /// Status line + headers, as received.
    head: String,
    /// Body octets actually received before the peer closed.
    body: Vec<u8>,
}

impl Observed {
    /// The `Content-Length` the server announced, which is what the
    /// client measures completeness against.
    fn announced_length(&self) -> usize {
        self.head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())?
            })
            .expect("response must announce Content-Length")
    }
}

/// Serve one `payload` through the real [`stream_blob`] wiring with the
/// real `Content-Length` header, fetch it over a loopback socket with a
/// literal HTTP/1.1 request, and report what arrived.
///
/// Deliberately a raw socket rather than an HTTP client: the assertion is
/// about octet counts against the announced length, and a client that
/// transparently retried or buffered would blur exactly that.
async fn serve_and_fetch(payload: Vec<u8>, chunk: usize, ending: Ending) -> Observed {
    let announced = payload.len();
    let payload = Arc::new(payload);

    let app = Router::new().route(
        "/blob",
        get(move || {
            let payload = Arc::clone(&payload);
            async move {
                let reader = ScriptedReader {
                    data: payload.as_ref().clone(),
                    pos: 0,
                    chunk,
                    ending,
                    park: false,
                };
                let mut headers = HeaderMap::new();
                headers.insert(CONTENT_TYPE, "application/octet-stream".parse().unwrap());
                headers.insert(CONTENT_LENGTH, announced.into());
                (
                    StatusCode::OK,
                    headers,
                    stream_blob(reader, DEFAULT_STREAM_CAPACITY),
                )
                    .into_response()
            }
        }),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let server = tokio::spawn(async move {
        // The client sends `Connection: close`, so this serves exactly one
        // connection and then the task is dropped with the test.
        let _ = axum::serve(listener, app).await;
    });

    let mut sock = TcpStream::connect(addr).await.expect("connect");
    sock.write_all(
        format!("GET /blob HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .expect("write request");

    // Read to EOF: whatever the server managed to deliver before it hung
    // up is precisely what the client has.
    let mut raw = Vec::new();
    sock.read_to_end(&mut raw).await.expect("read response");
    server.abort();

    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or_else(|| {
            panic!(
                "no header terminator in the {} bytes received: {:?}",
                raw.len(),
                String::from_utf8_lossy(&raw[..raw.len().min(200)])
            )
        });
    Observed {
        head: String::from_utf8_lossy(&raw[..split]).into_owned(),
        body: raw[split + 4..].to_vec(),
    }
}

/// 192 KiB — several `DEFAULT_STREAM_CAPACITY` chunks, so the body is
/// genuinely multi-chunk and a hold-back of the last one leaves the
/// client with most of the payload but not all of it.
fn payload() -> Vec<u8> {
    (0..192 * 1024).map(|i| (i % 251) as u8).collect()
}

/// **The finding.** A same-length substitution must not arrive as a
/// successful download: the client must end up short of the announced
/// `Content-Length`, which is the only completeness signal HTTP/1 gives
/// it for a length-delimited body.
///
/// Before the fix this reported 200 with `body.len() == 196608 ==
/// Content-Length` — a complete, successful response carrying the
/// substituted bytes.
#[tokio::test]
async fn same_length_integrity_failure_leaves_the_client_short_of_content_length() {
    let expected = payload();
    let observed = serve_and_fetch(
        expected.clone(),
        DEFAULT_STREAM_CAPACITY,
        Ending::IntegrityFailureAtEof,
    )
    .await;

    assert_eq!(
        observed.announced_length(),
        expected.len(),
        "the handler must still announce the true length; head was:\n{}",
        observed.head
    );
    assert!(
        observed.body.len() < expected.len(),
        "a same-length substitution reached the client as a complete body: \
         got {} of {} announced bytes",
        observed.body.len(),
        expected.len()
    );
    // Whatever did arrive is a prefix of the real bytes — the hold-back
    // withholds a suffix, it does not corrupt or reorder the stream.
    assert_eq!(
        observed.body.as_slice(),
        &expected[..observed.body.len()],
        "the delivered prefix must be unaltered"
    );
}

/// A blob smaller than one chunk is the boundary case: the whole body is
/// the final chunk, so the client must receive **nothing** rather than a
/// complete small file. Bounded by the stream capacity, which is what
/// keeps this a hold-back and not a buffer-the-blob.
#[tokio::test]
async fn single_chunk_integrity_failure_delivers_no_body_at_all() {
    let expected = b"the quick brown fox jumps over the lazy dog".to_vec();
    let observed = serve_and_fetch(
        expected.clone(),
        DEFAULT_STREAM_CAPACITY,
        Ending::IntegrityFailureAtEof,
    )
    .await;

    assert_eq!(observed.announced_length(), expected.len());
    assert!(
        observed.body.is_empty(),
        "a one-chunk blob must be withheld entirely; got {:?}",
        String::from_utf8_lossy(&observed.body)
    );
}

/// **Counter-test.** An intact blob still streams to completion with its
/// `Content-Length` intact and its bytes unchanged. The hold-back costs
/// one inner read of latency at the end of the body; it must cost
/// nothing else.
#[tokio::test]
async fn intact_blob_streams_to_completion_with_content_length_intact() {
    let expected = payload();
    let observed = serve_and_fetch(expected.clone(), DEFAULT_STREAM_CAPACITY, Ending::Eof).await;

    assert!(
        observed.head.starts_with("HTTP/1.1 200 OK"),
        "head was:\n{}",
        observed.head
    );
    assert_eq!(observed.announced_length(), expected.len());
    assert_eq!(
        observed.body, expected,
        "the whole payload must arrive byte-for-byte"
    );
}

/// **Counter-test.** The hold-back must not depend on the inner reader's
/// chunk sizes lining up with the stream capacity. A reader that dribbles
/// bytes out in small pieces still delivers the complete body.
#[tokio::test]
async fn intact_blob_streams_to_completion_under_small_inner_reads() {
    let expected = payload();
    let observed = serve_and_fetch(expected.clone(), 7, Ending::Eof).await;

    assert_eq!(observed.announced_length(), expected.len());
    assert_eq!(observed.body, expected);
}

/// A zero-length blob has no byte to hold back, and needs none: there is
/// exactly one zero-byte string, so a same-length substitution of it does
/// not exist. The case is here because it is the one place the hold-back
/// has nothing to withhold, and an empty 200 must still be well-formed.
#[tokio::test]
async fn empty_blob_serves_an_empty_body() {
    let observed = serve_and_fetch(Vec::new(), DEFAULT_STREAM_CAPACITY, Ending::Eof).await;

    assert_eq!(observed.announced_length(), 0);
    assert!(observed.body.is_empty());
}
