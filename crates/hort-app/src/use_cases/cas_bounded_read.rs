//! The one bounded CAS read for the paths that re-derive a projection
//! from a stored document's bytes.
//!
//! Two callers needed the same read and the obvious thing happened: each
//! grew its own copy of "open the stream, accumulate in chunks, refuse
//! over the ceiling". A third copy is what made this a module. The read
//! is small, but each copy carries three decisions a reader has to
//! re-derive — the chunk size, whether an over-ceiling blob is truncated
//! or refused, and what an absent object reports — and a copy that
//! answers one of them differently is a behaviour change nobody wrote
//! down.
//!
//! # The ceiling refuses rather than truncates
//!
//! A document read past its ceiling is not a document this caller can
//! reason about: the parse would see a prefix and derive a *shorter*
//! constituent set from it, which is exactly the silent narrowing a
//! deliverability answer must not do. So the read errors.
//! [`provenance_cascade`](crate::use_cases::provenance_cascade)'s own
//! reader deliberately truncates instead, because an over-ceiling
//! preimage there simply hashes wrong and the verifier rejects it; that
//! is a different contract and stays where it is.
//!
//! # Absence keeps its shape
//!
//! `StoragePort::get` reports a missing object as
//! [`DomainError::NotFound`], and this function passes that through
//! unflattened. Callers that walk a *tree* need the distinction: a
//! constituent with no CAS object is the ordinary state of a cold
//! pull-through and must not be read as a failure, while a backend that
//! errored is a failure. Flattening both into one string is what makes
//! "the blob is not here yet" indistinguishable from "the object store
//! is down", and those two deserve opposite answers.

use hort_domain::error::DomainError;
use hort_domain::ports::storage::StoragePort;
use hort_domain::types::ContentHash;
use tokio::io::AsyncReadExt;

use crate::error::{AppError, AppResult};

/// Read granularity. 64 KiB is the same chunk the worker-side bounded
/// CAS re-read uses — large enough that the syscall count stays
/// negligible for the kilobyte-scale documents this path reads, small
/// enough that the over-ceiling check trips before the buffer grows far
/// past the caller's limit.
pub(crate) const READ_CHUNK_BYTES: usize = 64 * 1024;

/// Read the CAS object at `hash`, refusing to buffer more than
/// `max_bytes`.
///
/// - absent object → `AppError::Domain(DomainError::NotFound { entity:
///   "content", .. })`, verbatim from the port;
/// - any other port failure, or a mid-stream failure → `AppError::Storage`;
/// - content past `max_bytes` → `AppError::Domain(DomainError::Validation)`,
///   never an unbounded allocation, so a corrupted multi-GB blob
///   mis-typed as a small document cannot exhaust process memory.
pub(crate) async fn read_cas_bounded(
    storage: &dyn StoragePort,
    hash: &ContentHash,
    max_bytes: usize,
) -> AppResult<Vec<u8>> {
    let mut stream = storage.get(hash).await.map_err(|e| match e {
        // Absence is a domain answer the caller may branch on; every
        // other failure is infrastructure.
        not_found @ DomainError::NotFound { .. } => AppError::Domain(not_found),
        other => AppError::Storage(other.to_string()),
    })?;
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; READ_CHUNK_BYTES];
    loop {
        let n = stream.read(&mut chunk).await.map_err(|e| {
            AppError::Storage(format!(
                "projection re-read of CAS blob {hash} failed mid-stream: {e}"
            ))
        })?;
        if n == 0 {
            break;
        }
        if buf.len() + n > max_bytes {
            return Err(AppError::Domain(DomainError::Validation(format!(
                "CAS blob {hash} content exceeds the {max_bytes}-byte projection \
                 re-read ceiling; refusing to buffer it"
            ))));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::use_cases::test_support::MockStoragePort;

    fn hash_of(seed: char) -> ContentHash {
        std::iter::repeat_n(seed, 64)
            .collect::<String>()
            .parse()
            .expect("synthetic sha256")
    }

    #[tokio::test]
    async fn content_under_the_ceiling_round_trips() {
        let storage = MockStoragePort::new();
        let hash = hash_of('a');
        storage.insert_content(hash.clone(), b"{\"schemaVersion\":2}".to_vec());
        assert_eq!(
            read_cas_bounded(&storage, &hash, 1024)
                .await
                .expect("a small document reads"),
            b"{\"schemaVersion\":2}".to_vec()
        );
    }

    /// The ceiling refuses. A truncating read would hand the caller a
    /// prefix and let it derive a shorter answer from it.
    #[tokio::test]
    async fn content_over_the_ceiling_is_refused_not_truncated() {
        let storage = MockStoragePort::new();
        let hash = hash_of('b');
        storage.insert_content(hash.clone(), vec![b'x'; 64]);
        let err = read_cas_bounded(&storage, &hash, 16)
            .await
            .expect_err("over-ceiling content is refused");
        assert!(
            matches!(err, AppError::Domain(DomainError::Validation(_))),
            "expected a Validation refusal, got {err:?}"
        );
    }

    /// The other half of the split: a failure that is **not** absence
    /// stays an infrastructure error. Driven on the mid-stream arm
    /// because that is the non-`NotFound` failure a `StoragePort` double
    /// can produce here — the mock's injectable `get` failure is itself a
    /// `NotFound`, which is the point of the test above.
    #[tokio::test]
    async fn a_mid_stream_failure_is_an_infrastructure_error_not_an_absence() {
        let storage = MockStoragePort::new();
        let hash = hash_of('d');
        storage.insert_content(hash.clone(), b"whole document".to_vec());
        storage.fail_next_get_truncated(hash.clone(), b"whol".to_vec());
        let err = read_cas_bounded(&storage, &hash, 1024)
            .await
            .expect_err("a stream that errors partway must not resolve");
        assert!(
            matches!(err, AppError::Storage(_)),
            "expected a Storage error, got {err:?}"
        );
    }

    /// Absence keeps its shape, because a tree walker has to tell "not
    /// local yet" apart from "the backend failed".
    #[tokio::test]
    async fn an_absent_object_reports_not_found_verbatim() {
        let storage = MockStoragePort::new();
        let err = read_cas_bounded(&storage, &hash_of('c'), 1024)
            .await
            .expect_err("an absent object cannot be read");
        assert!(
            matches!(
                err,
                AppError::Domain(DomainError::NotFound {
                    entity: "content",
                    ..
                })
            ),
            "expected a content NotFound, got {err:?}"
        );
    }
}
