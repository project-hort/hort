//! Make a forward-only CAS stream seekable without putting it in memory.
//!
//! Some stored artifacts are containers indexed at the tail: a ZIP's
//! member table is its central directory, so reading one member needs
//! `Seek`, and a `StoragePort::get` stream is forward-only. The usual
//! way out is to read the whole artifact into a `Vec<u8>` and seek
//! inside that — which makes peak memory a function of the artifact's
//! size rather than of the member being read, and an artifact's size is
//! not something the registry gets to choose. A pull-through ingest
//! accepts whatever the upstream serves.
//!
//! This module is the other way out, and it is the one ADR 0026 already
//! chose for the metadata pull-through path: spill the stream to a
//! temporary file and hand back a seekable handle onto it. Memory stays
//! at the copy buffer whatever the artifact weighs; the container's own
//! index then decides how much of the file is ever read back.
//!
//! The spill reads the stream **to EOF**, which is also what keeps
//! ADR 0003's read-verification intact: `StoragePort::get` verifies the
//! bytes it served against the hash they are stored under, and that
//! comparison only happens at EOF. A consumer that located its member
//! and stopped early would skip it.

use std::io::{Seek, SeekFrom};

use tokio::io::AsyncRead;

use hort_domain::error::{DomainError, DomainResult};

/// Copy `reader` to a temporary file and return it positioned at byte 0,
/// ready for `Read + Seek` use.
///
/// The returned handle is the *only* reference to the file: it has no
/// name in the filesystem, so it is reclaimed when the handle drops —
/// including on an early return or a panic further up. Nothing has to
/// remember to delete it.
///
/// Memory is bounded by `tokio::io::copy`'s internal buffer and is
/// independent of how many bytes flow through. `DomainError::Invariant`
/// on any filesystem or stream failure; the caller decides whether that
/// is fatal, because the answer differs by call site (a best-effort
/// metadata extraction degrades, an ingest does not).
pub async fn spill_to_seekable(
    reader: &mut (dyn AsyncRead + Send + Unpin),
) -> DomainResult<std::fs::File> {
    spill(reader)
        .await
        .map_err(|e| DomainError::Invariant(format!("spill stream to a temporary file: {e}")))
}

/// The spill itself, in `io::Result` so the four fallible steps share one
/// error mapping instead of four near-identical ones. Split out rather
/// than inlined because the caller's `DomainError` wrapping is the only
/// thing it adds.
async fn spill(reader: &mut (dyn AsyncRead + Send + Unpin)) -> std::io::Result<std::fs::File> {
    // `tempfile::tempfile()` opens and unlinks in one step, so the file
    // is unreachable by name from the moment it exists — no predictable
    // path for another process to swap or read.
    //
    // Not handed to the blocking pool, though it is a blocking syscall:
    // the consumer of the returned handle walks the archive
    // synchronously on this same thread, so protecting the one `open`
    // while leaving the inflate-and-scan in place would be ceremony
    // rather than protection.
    let file = tempfile::tempfile()?;

    let mut async_file = tokio::fs::File::from_std(file);
    // `copy` flushes the writer when the reader reaches EOF, so no
    // explicit flush follows: one would be a second syscall for a
    // guarantee already held.
    tokio::io::copy(reader, &mut async_file).await?;

    // The handle comes back at EOF; every consumer wants it at 0.
    let mut file = async_file.into_std().await;
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Read as _;

    /// The handle comes back rewound and carries exactly the bytes that
    /// went in — the property every caller relies on, since a handle
    /// left at EOF reads as an empty archive rather than as an error.
    #[tokio::test]
    async fn spill_round_trips_the_stream_and_rewinds_the_handle() {
        let payload: Vec<u8> = (0..=255u8).cycle().take(300_000).collect();
        let mut src = std::io::Cursor::new(payload.clone());
        let mut file = spill_to_seekable(&mut src).await.expect("spill");
        let mut out = Vec::new();
        file.read_to_end(&mut out).expect("read back");
        assert_eq!(out, payload);
    }

    /// An empty stream is a file of length zero, not an error: the
    /// callers' "is this a usable archive?" verdict belongs to the
    /// container parser, not to the spill.
    #[tokio::test]
    async fn spill_of_an_empty_stream_yields_an_empty_handle() {
        let mut src = std::io::Cursor::new(Vec::<u8>::new());
        let mut file = spill_to_seekable(&mut src).await.expect("spill");
        let mut out = Vec::new();
        file.read_to_end(&mut out).expect("read back");
        assert!(
            out.is_empty(),
            "expected an empty spill, got {} bytes",
            out.len()
        );
    }

    /// A stream that fails mid-copy is reported, not silently truncated
    /// into a short archive. The distinction matters at the call sites:
    /// a truncated ZIP parses as "no such member", which is the same
    /// answer a legitimately member-less archive gives.
    #[tokio::test]
    async fn spill_surfaces_a_mid_stream_read_failure() {
        struct FailsAfterFirstChunk {
            served: bool,
        }
        impl AsyncRead for FailsAfterFirstChunk {
            fn poll_read(
                mut self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                if self.served {
                    return std::task::Poll::Ready(Err(std::io::Error::other("backend went away")));
                }
                self.served = true;
                buf.put_slice(b"PK\x03\x04");
                std::task::Poll::Ready(Ok(()))
            }
        }

        let mut src = FailsAfterFirstChunk { served: false };
        let err = spill_to_seekable(&mut src)
            .await
            .expect_err("a failing stream must not spill successfully");
        match err {
            DomainError::Invariant(msg) => {
                assert!(
                    msg.contains("spill stream to a temporary file")
                        && msg.contains("backend went away"),
                    "unexpected message: {msg}"
                );
            }
            other => panic!("expected Invariant, got {other:?}"),
        }
    }
}
