use futures::stream::BoxStream;
use tokio::io::AsyncRead;

use crate::error::{DomainError, DomainResult};
use crate::types::{ByteRange, ContentHash};

use super::BoxFuture;

/// Result of a successful CAS put operation.
///
/// `created` distinguishes a fresh write (`true` — this call finalised a new
/// CAS object) from a dedup (`false` — `exists(hash)` short-circuited the
/// write because identical content was already present). Any future cleanup
/// or GC primitive must honour this: deleting a deduped object would corrupt
/// other artifacts that reference it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PutResult {
    pub hash: ContentHash,
    pub size_bytes: u64,
    pub created: bool,
}

/// Item yielded by [`StoragePort::list_all`].
///
/// The CAS walk can encounter per-key errors (filesystem EACCES, S3 head
/// failures, malformed filenames that don't parse as hashes) without the
/// walk itself being unrecoverable. Surfacing per-item errors as a data
/// variant lets the `CasScrubUseCase` record them in the scrub report
/// without short-circuiting the scan — one bad blob does not stop the
/// rest of the audit.
///
/// **Signature note.** The alternative is
/// `BoxStream<'_, DomainResult<ContentHash>>`. We picked this form
/// because the scrubber wants to continue past individual failures and
/// record them as `read_error` in the metric; propagating them via
/// `DomainResult` would force every consumer to distinguish "stream
/// terminated" from "one item failed." With `StreamItem`, the stream
/// only ends on EOF; errors are data.
#[derive(Debug, Clone)]
pub enum StreamItem {
    /// A successfully-parsed content hash listed by the backend.
    Hash(ContentHash),
    /// A key was listed but could not be turned into a `ContentHash`
    /// (unexpected filename shape, stat/head failure, access-denied).
    /// `key` is the backend-local path or key for diagnostics only;
    /// never emitted as a metric label (free-form string, cardinality
    /// hazard).
    ReadError { key: String, err: DomainError },
    /// A whole shard directory was abandoned mid-walk after the
    /// adapter's per-step retry was exhausted. The
    /// remaining entries under `key` were never
    /// observed by the scrub. Distinct from `ReadError` because the
    /// loss is at the directory granularity, not a single blob; the
    /// `CasScrubUseCase` rolls these into [`ScrubReport::shards_truncated`]
    /// so operators see a positive count when the scrub output is
    /// partial. Object-store backends (flat key listings) do not emit
    /// this variant — only the sharded filesystem walk does.
    ShardTruncated { key: String, err: DomainError },
}

/// Outbound port for content-addressable storage.
///
/// Callers supply a byte stream and receive a content hash. Callers never
/// construct storage keys — the hash is derived from the content by the
/// adapter. SHA-256 is computed incrementally as chunks flow through `put()`,
/// so memory usage is bounded regardless of artifact size.
///
/// `delete` is exposed as a narrowly-scoped rollback primitive for the
/// `IngestUseCase` declared-hash mismatch path (ADR 0003): when
/// the hash of the streamed body disagrees with `declared_sha256`, the
/// use case removes the freshly-put blob **only if no other row
/// references it** (`find_by_checksum` empty). Deletion is otherwise an
/// internal GC concern — `CasScrubUseCase` reaps
/// orphans at rest; request-serving handlers MUST NOT call `delete`.
pub trait StoragePort: Send + Sync {
    /// Store content from a stream, compute SHA-256 incrementally, return
    /// the hash and total byte count. Idempotent: re-putting identical
    /// content is a no-op.
    fn put(
        &self,
        stream: Box<dyn AsyncRead + Send + Unpin>,
    ) -> BoxFuture<'_, DomainResult<PutResult>>;

    /// Retrieve content as a stream.
    fn get(
        &self,
        hash: &ContentHash,
    ) -> BoxFuture<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>>;

    /// Retrieve a byte range from the content at `hash` as a stream.
    ///
    /// Implementations MUST seek (not read-and-discard) so a 1 GB blob
    /// served at `Range: bytes=$LAST-` does not buffer the
    /// preceding bytes. The returned `AsyncRead` must yield exactly
    /// the resolved-range bytes — no extra prefix, no extra suffix.
    ///
    /// **Caller contract.** The HTTP layer pre-validates bounds against
    /// the object's size and rejects unsatisfiable ranges with `416
    /// Range Not Satisfiable` per RFC 7233 §4.4 BEFORE calling this
    /// method. Specifically:
    ///
    /// - For `ByteRange::Inclusive { start, end }` the caller has
    ///   verified `start <= end` and `end < size` (an `end >= size`
    ///   request is RFC-clamped to `end = size - 1` at the HTTP
    ///   layer; an `end < start` request is RFC-unsatisfiable).
    /// - For `ByteRange::From { start }` the caller has verified
    ///   `start < size`.
    /// - For `ByteRange::Suffix { last }` the caller has verified
    ///   `last > 0`. A `last > size` request is RFC-clamped to the
    ///   whole object at the adapter ("If the selected representation
    ///   is shorter than the specified suffix-length, the entire
    ///   representation is used" — RFC 7233 §2.1); the HTTP layer
    ///   does not pre-clamp suffixes because the size resolution is
    ///   the adapter's natural concern.
    ///
    /// Out-of-bounds variants delivered to the adapter despite this
    /// contract MAY return a `DomainError::Invariant` or any other
    /// error variant the adapter sees fit; behaviour is unspecified
    /// because the HTTP layer is the contractual gate.
    ///
    /// Used by the OCI blob handler for `Range`-honouring `GET /v2/<
    /// name>/blobs/<digest>` so kubelet /
    /// containerd can resume interrupted layer downloads. No other
    /// request-serving path uses this method today.
    fn get_range(
        &self,
        hash: &ContentHash,
        range: ByteRange,
    ) -> BoxFuture<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>>;

    /// Check if content exists.
    fn exists(&self, hash: &ContentHash) -> BoxFuture<'_, DomainResult<bool>>;

    /// Remove a CAS blob by content hash.
    ///
    /// Used exclusively by `IngestUseCase::ingest` on the declared-hash
    /// mismatch rollback path (ADR 0003). The use case
    /// pre-checks `ArtifactRepository::find_by_checksum` and only calls
    /// `delete` when no row references the hash — the adapter is NOT
    /// responsible for reference-counting.
    ///
    /// Idempotent from the caller's perspective: a `NotFound` return is
    /// acceptable (the blob is already gone — nothing to do). Adapters
    /// MAY surface `NotFound` as `Err(DomainError::NotFound { entity:
    /// "content", id: <hash> })` or as `Ok(())`; the use case logs and
    /// continues either way.
    ///
    /// Default implementation returns `Ok(())` — the no-op is safe for
    /// test doubles and WASM stubs that do not durably store bytes.
    /// Production adapters override with a real delete.
    fn delete(&self, _hash: &ContentHash) -> BoxFuture<'_, DomainResult<()>> {
        Box::pin(async { Ok(()) })
    }

    /// Size in bytes of the stored content at `hash`.
    ///
    /// Returns `DomainError::NotFound { entity: "content", id: <hash> }`
    /// when the hash is absent (mirrors [`Self::get`]'s not-found shape).
    /// Adapters stat the object — filesystem: `metadata().len()`; object
    /// stores: `HEAD` returning `Content-Length`; mocks: the in-memory
    /// content's length. No bytes are streamed.
    ///
    /// Consumer: [`IngestUseCase::register_by_hash`] on the
    /// `source_repo = None` branch, where no `Artifact` row may yet
    /// reference the hash (Phase 4 proxy/replication) so the projection
    /// row needs an authoritative size from the CAS itself. The method
    /// is NOT on any request-serving read path; `size_bytes` for a
    /// downloaded artifact comes from the `Artifact` row, not from a
    /// live stat.
    fn size_of(&self, hash: &ContentHash) -> BoxFuture<'_, DomainResult<u64>>;

    /// Enumerate every content hash currently stored by this adapter.
    ///
    /// The return type is a stream so that backends with millions of blobs
    /// stay memory-bounded (no `Vec<ContentHash>` that would buffer the
    /// entire CAS). Per-item errors are surfaced as
    /// [`StreamItem::ReadError`] data rather than as a `DomainResult` arm;
    /// see the [`StreamItem`] docstring for the rationale.
    ///
    /// Ordering is unspecified — callers (`CasScrubUseCase`) that require
    /// a deterministic sweep must sort or shuffle client-side. The
    /// scrubber does not.
    ///
    /// Consumed by [`CasScrubUseCase`](../../../../../hort_app/use_cases/cas_scrub_use_case/struct.CasScrubUseCase.html).
    /// No HTTP handler may call this method;
    /// the storage walk is operator-triggered through the `hort-server
    /// scrub` subcommand only.
    ///
    /// Default implementation yields an empty stream. Production
    /// adapters override with a real walk; test doubles that don't
    /// exercise the scrub path inherit the default without needing to
    /// fabricate an empty impl manually.
    fn list_all(&self) -> BoxFuture<'_, DomainResult<BoxStream<'_, StreamItem>>> {
        Box::pin(async {
            let s: BoxStream<'_, StreamItem> = Box::pin(futures::stream::empty());
            Ok(s)
        })
    }

    /// Coarse backend identifier for metric emission.
    ///
    /// Must be one of `"filesystem"` or `"object_store"` — the known-set
    /// enumerated in `docs/metrics-catalog.md` for
    /// `hort_cas_scrub_checks_total{backend}`. The finer-grained label
    /// used by `hort_storage_operations_total` (`filesystem`, `s3`, `gcs`,
    /// `azure`, `memory`) is an adapter-internal concern; the scrubber
    /// treats all object-store backends uniformly.
    ///
    /// Default implementation returns `"unknown"`; each shipped adapter
    /// overrides with its known label. Mocks in `test-support` inherit
    /// the default, which never produces metric pressure because tests
    /// either inspect the return value directly or assert on the exact
    /// label the test mock returns.
    fn backend_label(&self) -> &'static str {
        "unknown"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time assertion that `StoragePort` is dyn-compatible.
    #[test]
    fn port_is_dyn_compatible() {
        // Compile-time: resolves only if the trait is dyn-compatible.
        // Runtime: size_of call executes in the test body for coverage.
        let _ = size_of::<&dyn StoragePort>();
    }

    /// `StreamItem::Hash` round-trips the supplied hash and is `Clone`.
    #[test]
    fn stream_item_hash_variant_carries_hash() {
        let h: ContentHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .unwrap();
        let item = StreamItem::Hash(h.clone());
        match item {
            StreamItem::Hash(got) => assert_eq!(got, h),
            StreamItem::ReadError { .. } | StreamItem::ShardTruncated { .. } => {
                panic!("expected Hash variant")
            }
        }
    }

    /// `StreamItem::ReadError` carries the key for diagnostics and the
    /// underlying `DomainError`.
    #[test]
    fn stream_item_read_error_variant_carries_key_and_error() {
        let item = StreamItem::ReadError {
            key: "cas/aa/bb/bogus".into(),
            err: DomainError::Invariant("test".into()),
        };
        match item {
            StreamItem::ReadError { key, err } => {
                assert_eq!(key, "cas/aa/bb/bogus");
                assert!(err.to_string().contains("test"));
            }
            StreamItem::Hash(_) | StreamItem::ShardTruncated { .. } => {
                panic!("expected ReadError variant")
            }
        }
    }

    /// `StreamItem::ShardTruncated` carries the key for diagnostics and
    /// the underlying `DomainError`.
    /// The streaming filesystem walker emits this when a per-step retry
    /// is exhausted; consumers (`CasScrubUseCase`) increment
    /// `ScrubReport::shards_truncated`.
    #[test]
    fn stream_item_shard_truncated_variant_carries_key_and_error() {
        let item = StreamItem::ShardTruncated {
            key: "cas/aa/bb".into(),
            err: DomainError::Invariant("EINTR x2".into()),
        };
        match item {
            StreamItem::ShardTruncated { key, err } => {
                assert_eq!(key, "cas/aa/bb");
                assert!(err.to_string().contains("EINTR"));
            }
            StreamItem::Hash(_) | StreamItem::ReadError { .. } => {
                panic!("expected ShardTruncated variant")
            }
        }
    }

    /// A minimal impl to pin the trait's default `backend_label` and to
    /// exercise the domain-side contract without pulling in the adapter
    /// crates (they have their own tests).
    struct NoopStorage;

    impl StoragePort for NoopStorage {
        fn put(
            &self,
            _stream: Box<dyn AsyncRead + Send + Unpin>,
        ) -> BoxFuture<'_, DomainResult<PutResult>> {
            Box::pin(async { unreachable!("test noop") })
        }
        fn get(
            &self,
            _hash: &ContentHash,
        ) -> BoxFuture<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>> {
            Box::pin(async { unreachable!("test noop") })
        }
        fn get_range(
            &self,
            _hash: &ContentHash,
            _range: ByteRange,
        ) -> BoxFuture<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>> {
            Box::pin(async { unreachable!("test noop") })
        }
        fn exists(&self, _hash: &ContentHash) -> BoxFuture<'_, DomainResult<bool>> {
            Box::pin(async { unreachable!("test noop") })
        }
        fn size_of(&self, _hash: &ContentHash) -> BoxFuture<'_, DomainResult<u64>> {
            Box::pin(async { unreachable!("test noop") })
        }
        fn list_all(&self) -> BoxFuture<'_, DomainResult<BoxStream<'_, StreamItem>>> {
            Box::pin(async {
                let s: BoxStream<'_, StreamItem> = Box::pin(futures::stream::empty());
                Ok(s)
            })
        }
    }

    #[test]
    fn backend_label_default_is_unknown() {
        assert_eq!(NoopStorage.backend_label(), "unknown");
    }

    /// Default `delete` is a successful no-op — stubs that do not
    /// durably store bytes must not error on the rollback path.
    #[tokio::test]
    async fn noop_delete_default_is_ok() {
        let h: ContentHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .unwrap();
        NoopStorage.delete(&h).await.unwrap();
    }

    /// Default `list_all` yields an empty stream — adapters that don't
    /// override cannot deadlock the scrubber.
    #[tokio::test]
    async fn noop_list_all_is_empty() {
        use futures::StreamExt;
        let s = NoopStorage.list_all().await.unwrap();
        let items: Vec<_> = s.collect().await;
        assert!(items.is_empty());
    }
}
