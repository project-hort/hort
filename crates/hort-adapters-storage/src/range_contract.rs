//! Generic `StoragePort::get_range` contract suite. Parameterised over
//! a `StoragePort` factory so both the filesystem and the object-store
//! (in-memory) adapters in this crate can be exercised against the same
//! byte-exact assertions.
//!
//! The HTTP layer pre-validates bounds against the object's size; the
//! adapter only sees ranges that the caller has classified as
//! satisfiable. This contract therefore exercises the satisfiable
//! variants — `Inclusive`, `From`, `Suffix` — across a fixed
//! 1024-byte payload, plus the suffix-clamp boundary documented on
//! the trait.
//!
//! Each test asserts BYTE-EXACT equality against an offset+length
//! slice of the expected content. A whole-content comparison is
//! insufficient — an implementation that reads from offset 0 and then
//! truncates to `len` produces the right number of bytes but the
//! wrong content for any non-prefix range, and the correct test must
//! catch that.

use std::sync::Arc;

use tokio::io::AsyncReadExt;

use hort_domain::ports::storage::StoragePort;
use hort_domain::types::{ByteRange, ContentHash};

/// Fixed 1024-byte payload — distinct value per byte position so a
/// mis-aligned slice fails the byte-exact assertion immediately.
pub(crate) fn fixture_payload() -> Vec<u8> {
    (0..1024u32).map(|i| (i % 256) as u8).collect()
}

/// Helper: stream every byte from `reader` into a `Vec<u8>`.
async fn drain<R>(mut reader: R) -> Vec<u8>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).await.unwrap();
    buf
}

/// Run the full contract suite against `storage` for `(hash,
/// content)`. The hash MUST be the SHA-256 of `content` and the
/// adapter MUST already have the content stored.
pub(crate) async fn run_contract<S: StoragePort + ?Sized>(
    storage: Arc<S>,
    hash: ContentHash,
    content: &[u8],
) {
    let size = content.len() as u64;
    assert!(size >= 100, "contract fixture must be at least 100 bytes");

    // ---- Inclusive: prefix slice -----------------------------------
    let r = storage
        .get_range(&hash, ByteRange::Inclusive { start: 0, end: 99 })
        .await
        .expect("get_range Inclusive 0-99");
    let bytes = drain(r).await;
    assert_eq!(
        bytes,
        &content[0..100],
        "Inclusive 0-99 must equal first 100 bytes"
    );
    assert_eq!(bytes.len(), 100);

    // ---- Inclusive: middle slice -----------------------------------
    let r = storage
        .get_range(
            &hash,
            ByteRange::Inclusive {
                start: 50,
                end: 199,
            },
        )
        .await
        .expect("get_range Inclusive 50-199");
    let bytes = drain(r).await;
    assert_eq!(
        bytes,
        &content[50..200],
        "Inclusive 50-199 must equal bytes 50..200"
    );
    assert_eq!(bytes.len(), 150);

    // ---- Inclusive: single byte ------------------------------------
    let r = storage
        .get_range(
            &hash,
            ByteRange::Inclusive {
                start: 500,
                end: 500,
            },
        )
        .await
        .expect("get_range Inclusive 500-500");
    let bytes = drain(r).await;
    assert_eq!(bytes, vec![content[500]], "single-byte slice must match");

    // ---- Inclusive: tail (end == size - 1) -------------------------
    let r = storage
        .get_range(
            &hash,
            ByteRange::Inclusive {
                start: 1000,
                end: 1023,
            },
        )
        .await
        .expect("get_range Inclusive 1000-1023");
    let bytes = drain(r).await;
    assert_eq!(
        bytes,
        &content[1000..1024],
        "Inclusive 1000-1023 must equal tail"
    );
    assert_eq!(bytes.len(), 24);

    // ---- From: from start ------------------------------------------
    let r = storage
        .get_range(&hash, ByteRange::From { start: 100 })
        .await
        .expect("get_range From 100");
    let bytes = drain(r).await;
    assert_eq!(bytes, &content[100..], "From 100 must equal bytes 100..");
    assert_eq!(bytes.len(), 1024 - 100);

    // ---- From: start = 0 (whole content) ---------------------------
    let r = storage
        .get_range(&hash, ByteRange::From { start: 0 })
        .await
        .expect("get_range From 0");
    let bytes = drain(r).await;
    assert_eq!(bytes, content, "From 0 must equal entire content");

    // ---- From: last byte -------------------------------------------
    let r = storage
        .get_range(&hash, ByteRange::From { start: 1023 })
        .await
        .expect("get_range From 1023");
    let bytes = drain(r).await;
    assert_eq!(
        bytes,
        vec![content[1023]],
        "From 1023 must equal final byte"
    );

    // ---- Suffix: short suffix --------------------------------------
    let r = storage
        .get_range(&hash, ByteRange::Suffix { last: 50 })
        .await
        .expect("get_range Suffix 50");
    let bytes = drain(r).await;
    assert_eq!(
        bytes,
        &content[(1024 - 50)..],
        "Suffix 50 must equal last 50 bytes"
    );
    assert_eq!(bytes.len(), 50);

    // ---- Suffix: == size (whole content) ---------------------------
    let r = storage
        .get_range(&hash, ByteRange::Suffix { last: 1024 })
        .await
        .expect("get_range Suffix 1024");
    let bytes = drain(r).await;
    assert_eq!(bytes, content, "Suffix == size must equal whole content");

    // ---- Suffix: > size (RFC clamp) --------------------------------
    // RFC 7233 §2.1: "If the selected representation is shorter than
    // the specified suffix-length, the entire representation is
    // used." The HTTP layer does not pre-clamp; the adapter MUST.
    let r = storage
        .get_range(&hash, ByteRange::Suffix { last: 999_999 })
        .await
        .expect("get_range Suffix > size");
    let bytes = drain(r).await;
    assert_eq!(
        bytes, content,
        "Suffix > size must clamp to whole content per RFC 7233 §2.1"
    );
}
