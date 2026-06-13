use std::sync::Arc;

use futures::stream::BoxStream;
use futures::StreamExt;
use object_store::{ObjectStore, ObjectStoreExt};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio_util::io::StreamReader;
use tracing::{debug, warn};

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::storage::{PutResult, StoragePort, StreamItem};
use hort_domain::ports::BoxFuture;
use hort_domain::types::{ByteRange, ContentHash};

use crate::cas::cas_path;
use crate::integrity::VerifyingReader;
use crate::metrics::{emit_integrity_failure, values, MetricGuard};

/// Read buffer size — 64 KB per concurrent transfer.
const CHUNK_SIZE: usize = 64 * 1024;

/// Minimum part size for S3-compatible multipart uploads (5 MiB).
/// Parts smaller than this cause errors on most object stores.
const MIN_PART_SIZE: usize = 5 * 1024 * 1024;

/// Object-store backed content-addressable storage (S3, GCS, Azure, local).
///
/// Wraps the `object_store` crate which abstracts across cloud providers.
/// Uses multipart upload to keep memory bounded — a 2 GB artifact uses
/// ~5 MB of buffer, not 2 GB.
pub struct ObjectStoreStorage {
    store: Arc<dyn ObjectStore>,
    /// Backend label emitted with every metric. Supplied by the caller so
    /// deployments with S3, GCS, Azure, or (in tests) in-memory each get a
    /// distinct `backend` series.
    backend: &'static str,
}

impl ObjectStoreStorage {
    /// Construct a new object-store-backed CAS.
    ///
    /// `backend_label` must be one of the `values::BACKEND_*` constants in
    /// `crate::metrics::values` (`s3`, `gcs`, `azure`, `memory`, ...).
    pub fn new(store: Arc<dyn ObjectStore>, backend_label: &'static str) -> Self {
        Self {
            store,
            backend: backend_label,
        }
    }
}

/// Map an `object_store::Error` to a `DomainError`, using the hash for context.
fn map_object_store_error(e: &object_store::Error, hash: &str) -> DomainError {
    match e {
        object_store::Error::NotFound { .. } => DomainError::NotFound {
            entity: "content",
            id: hash.to_owned(),
        },
        other => DomainError::Invariant(format!("object store error: {other}")),
    }
}

impl StoragePort for ObjectStoreStorage {
    fn put(
        &self,
        mut stream: Box<dyn AsyncRead + Send + Unpin>,
    ) -> BoxFuture<'_, DomainResult<PutResult>> {
        let backend = self.backend;
        Box::pin(async move {
            let mut guard = MetricGuard::new(backend, values::OPERATION_PUT);
            // We need a temporary path for the multipart upload. We don't know
            // the hash yet, so use a UUID-based staging path.
            let staging_path: object_store::path::Path =
                format!(".staging/{}", uuid::Uuid::new_v4()).into();

            let mut upload = self.store.put_multipart(&staging_path).await.map_err(|e| {
                warn!(error = %e, "failed to initiate multipart upload");
                DomainError::Invariant(format!("storage upload init failed: {e}"))
            })?;

            let mut hasher = Sha256::new();
            let mut read_buf = vec![0u8; CHUNK_SIZE];
            let mut part_buf = Vec::with_capacity(MIN_PART_SIZE);
            let mut total_bytes: u64 = 0;

            loop {
                let n = stream.read(&mut read_buf).await.map_err(|e| {
                    warn!(error = %e, "failed to read from input stream");
                    DomainError::Invariant(format!("storage read failed: {e}"))
                })?;
                if n == 0 {
                    break;
                }
                total_bytes += n as u64;
                hasher.update(&read_buf[..n]);
                part_buf.extend_from_slice(&read_buf[..n]);

                if part_buf.len() >= MIN_PART_SIZE {
                    let payload =
                        std::mem::replace(&mut part_buf, Vec::with_capacity(MIN_PART_SIZE));
                    upload.put_part(payload.into()).await.map_err(|e| {
                        warn!(error = %e, "failed to upload part");
                        DomainError::Invariant(format!("storage part upload failed: {e}"))
                    })?;
                }
            }

            // Flush remaining bytes as the final part (may be < MIN_PART_SIZE).
            if !part_buf.is_empty() {
                upload.put_part(part_buf.into()).await.map_err(|e| {
                    warn!(error = %e, "failed to upload final part");
                    DomainError::Invariant(format!("storage part upload failed: {e}"))
                })?;
            }

            let hash_hex = format!("{:x}", hasher.finalize());
            let hash: ContentHash = hash_hex.parse().map_err(|e| {
                DomainError::Invariant(format!("SHA-256 produced invalid hex: {e}"))
            })?;

            let final_path: object_store::path::Path = cas_path(&hash).into();

            // Check for dedup: if content already exists, abort the staging
            // upload and return the hash.
            let already_exists = self.store.head(&final_path).await.is_ok();

            if already_exists {
                debug!(%hash, "deduplicated");
                let _ = upload.abort().await;
                let _ = self.store.delete(&staging_path).await;
                guard.finish_success();
                guard.mark_dedup();
                return Ok(PutResult {
                    hash,
                    size_bytes: total_bytes,
                    created: false,
                });
            }

            // Complete the multipart to staging path.
            upload.complete().await.map_err(|e| {
                warn!(error = %e, "failed to complete multipart upload");
                DomainError::Invariant(format!("storage upload complete failed: {e}"))
            })?;

            // Copy from staging to final CAS path, then clean up staging.
            self.store
                .copy(&staging_path, &final_path)
                .await
                .map_err(|e| {
                    warn!(%hash, error = %e, "failed to copy to final path");
                    DomainError::Invariant(format!("storage copy failed: {e}"))
                })?;
            let _ = self.store.delete(&staging_path).await;

            debug!(%hash, "stored");
            guard.finish_success();
            Ok(PutResult {
                hash,
                size_bytes: total_bytes,
                created: true,
            })
        })
    }

    fn get(
        &self,
        hash: &ContentHash,
    ) -> BoxFuture<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>> {
        let backend = self.backend;
        let path: object_store::path::Path = cas_path(hash).into();
        let hash_display = hash.to_string();
        let expected_hash = hash.clone();
        Box::pin(async move {
            let mut guard = MetricGuard::new(backend, values::OPERATION_GET);
            let result = match self.store.get(&path).await {
                Ok(r) => r,
                Err(e) if matches!(e, object_store::Error::NotFound { .. }) => {
                    debug!(hash = %hash_display, "not found");
                    guard.finish_not_found();
                    return Err(map_object_store_error(&e, &hash_display));
                }
                Err(e) => {
                    warn!(hash = %hash_display, error = %e, "get failed");
                    return Err(map_object_store_error(&e, &hash_display));
                }
            };

            // Convert the byte stream into AsyncRead via StreamReader.
            let byte_stream = result
                .into_stream()
                .map(|chunk_result| chunk_result.map_err(std::io::Error::other));
            let reader = StreamReader::new(byte_stream);

            debug!(hash = %hash_display, "retrieved");
            guard.finish_success();
            // Wrap the reader in a streaming SHA-256 verifier (ADR 0003).
            // Same discipline as the filesystem adapter — adapter
            // invariant, not a port contract change. Mismatch fires
            // `hort_storage_integrity_failures_total{backend}`.
            let verifying = VerifyingReader::new(
                reader,
                expected_hash,
                Some(Box::new(move || emit_integrity_failure(backend))),
            );
            Ok(Box::new(verifying) as Box<dyn AsyncRead + Send + Unpin>)
        })
    }

    /// Range-honouring read.
    ///
    /// Translates the domain `ByteRange` to `object_store::GetRange`
    /// and dispatches via `get_opts`. The object_store crate handles
    /// the per-backend HTTP `Range` header / multipart-fetch detail.
    ///
    /// Suffix > size is RFC-clamped at the call site (we resolve the
    /// object size via `head` first) so the underlying object_store's
    /// own validation does not error on `Suffix(very_large)`.
    ///
    /// Note: integrity verification (`VerifyingReader`) is intentionally
    /// SKIPPED for range reads — see the FilesystemStorage rationale.
    fn get_range(
        &self,
        hash: &ContentHash,
        range: ByteRange,
    ) -> BoxFuture<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>> {
        let backend = self.backend;
        let path: object_store::path::Path = cas_path(hash).into();
        let hash_display = hash.to_string();
        Box::pin(async move {
            let mut guard = MetricGuard::new(backend, values::OPERATION_GET);

            // Stat to resolve `From` / clamp `Suffix` against the
            // actual object size. NotFound mirrors `get`'s shape.
            let size = match self.store.head(&path).await {
                Ok(meta) => meta.size,
                Err(object_store::Error::NotFound { .. }) => {
                    debug!(hash = %hash_display, "get_range: not found");
                    guard.finish_not_found();
                    return Err(DomainError::NotFound {
                        entity: "content",
                        id: hash_display,
                    });
                }
                Err(e) => {
                    warn!(hash = %hash_display, error = %e, "get_range head failed");
                    return Err(map_object_store_error(&e, &hash_display));
                }
            };

            let get_range = match range {
                ByteRange::Inclusive { start, end } => {
                    // object_store::GetRange::Bounded uses an
                    // exclusive end; the domain range is inclusive.
                    object_store::GetRange::Bounded(start..(end + 1))
                }
                ByteRange::From { start } => object_store::GetRange::Offset(start),
                ByteRange::Suffix { last } => {
                    if last >= size {
                        // RFC clamp — object_store's Suffix(N) where N
                        // > size errors on some backends; explicit
                        // whole-content range avoids that.
                        object_store::GetRange::Bounded(0..size)
                    } else {
                        object_store::GetRange::Suffix(last)
                    }
                }
            };

            let opts = object_store::GetOptions {
                range: Some(get_range),
                ..Default::default()
            };

            let result = match self.store.get_opts(&path, opts).await {
                Ok(r) => r,
                Err(object_store::Error::NotFound { .. }) => {
                    debug!(hash = %hash_display, "get_range: not found post-head (race)");
                    guard.finish_not_found();
                    return Err(DomainError::NotFound {
                        entity: "content",
                        id: hash_display,
                    });
                }
                Err(e) => {
                    warn!(hash = %hash_display, error = %e, "get_range failed");
                    return Err(map_object_store_error(&e, &hash_display));
                }
            };

            let byte_stream = result
                .into_stream()
                .map(|chunk_result| chunk_result.map_err(std::io::Error::other));
            let reader = StreamReader::new(byte_stream);

            debug!(hash = %hash_display, "range retrieved");
            guard.finish_success();
            // No verifier wrap — see method docstring.
            Ok(Box::new(reader) as Box<dyn AsyncRead + Send + Unpin>)
        })
    }

    fn exists(&self, hash: &ContentHash) -> BoxFuture<'_, DomainResult<bool>> {
        let backend = self.backend;
        let path: object_store::path::Path = cas_path(hash).into();
        let hash_display = hash.to_string();
        Box::pin(async move {
            let mut guard = MetricGuard::new(backend, values::OPERATION_EXISTS);
            match self.store.head(&path).await {
                Ok(_) => {
                    debug!(hash = %hash_display, exists = true, "exists check");
                    guard.finish_success();
                    Ok(true)
                }
                Err(object_store::Error::NotFound { .. }) => {
                    debug!(hash = %hash_display, exists = false, "exists check");
                    guard.finish_success();
                    Ok(false)
                }
                Err(e) => {
                    warn!(hash = %hash_display, error = %e, "exists check failed");
                    Err(DomainError::Invariant(format!(
                        "storage exists check failed: {e}"
                    )))
                }
            }
        })
    }

    fn size_of(&self, hash: &ContentHash) -> BoxFuture<'_, DomainResult<u64>> {
        let backend = self.backend;
        let path: object_store::path::Path = cas_path(hash).into();
        let hash_display = hash.to_string();
        Box::pin(async move {
            let mut guard = MetricGuard::new(backend, values::OPERATION_EXISTS);
            match self.store.head(&path).await {
                Ok(meta) => {
                    let size = meta.size;
                    debug!(hash = %hash_display, size, "size_of");
                    guard.finish_success();
                    Ok(size)
                }
                Err(object_store::Error::NotFound { .. }) => {
                    debug!(hash = %hash_display, "size_of: not found");
                    guard.finish_not_found();
                    Err(DomainError::NotFound {
                        entity: "content",
                        id: hash_display,
                    })
                }
                Err(e) => {
                    warn!(hash = %hash_display, error = %e, "size_of head failed");
                    Err(DomainError::Invariant(format!(
                        "storage size_of failed: {e}"
                    )))
                }
            }
        })
    }

    /// Remove the CAS object at `hash`.
    ///
    /// Called from the ingest declared-hash mismatch rollback path.
    /// Missing keys yield `DomainError::NotFound` — the use case treats
    /// this as a benign no-op.
    fn delete(&self, hash: &ContentHash) -> BoxFuture<'_, DomainResult<()>> {
        let backend = self.backend;
        let path: object_store::path::Path = cas_path(hash).into();
        let hash_display = hash.to_string();
        Box::pin(async move {
            let mut guard = MetricGuard::new(backend, values::OPERATION_DELETE);
            // HEAD the object for its size BEFORE the delete so a
            // successful removal can attribute the exact bytes reclaimed
            // to `hort_storage_blobs_deleted_bytes_total` (ADR 0020).
            // A HEAD failure here is non-fatal — the delete still
            // proceeds; we simply cannot attribute its byte count
            // (size `None` ⇒ no increment, never a fabricated value).
            let size_before: Option<u64> = match self.store.head(&path).await {
                Ok(meta) => Some(meta.size),
                Err(_) => None,
            };
            match self.store.delete(&path).await {
                Ok(()) => {
                    debug!(hash = %hash_display, "deleted");
                    guard.finish_success();
                    if let Some(bytes) = size_before {
                        crate::metrics::emit_blob_deleted_bytes(backend, bytes);
                    }
                    Ok(())
                }
                Err(object_store::Error::NotFound { .. }) => {
                    debug!(hash = %hash_display, "delete: not found");
                    guard.finish_not_found();
                    Err(DomainError::NotFound {
                        entity: "content",
                        id: hash_display,
                    })
                }
                Err(e) => {
                    warn!(hash = %hash_display, error = %e, "delete failed");
                    Err(map_object_store_error(&e, &hash_display))
                }
            }
        })
    }

    /// List every CAS blob under the `cas/` prefix. Used by the
    /// `CasScrubUseCase`.
    ///
    /// We use `ObjectStore::list(Some("cas/"))` rather than
    /// `list_with_delimiter` because the scrubber wants the full set
    /// of leaf keys, not the hierarchical listing a delimiter produces.
    /// The stream is mapped in-place: object-store errors become
    /// `StreamItem::ReadError`, and object keys are parsed into
    /// `ContentHash` (bad keys → `ReadError`).
    fn list_all(&self) -> BoxFuture<'_, DomainResult<BoxStream<'_, StreamItem>>> {
        let store = Arc::clone(&self.store);
        Box::pin(async move {
            let prefix: object_store::path::Path = "cas".into();
            let listing = store.list(Some(&prefix));
            let mapped = listing.map(|res| match res {
                Ok(meta) => {
                    let location = meta.location.as_ref().to_string();
                    let name = location.rsplit('/').next().unwrap_or("").to_string();
                    match name.parse::<ContentHash>() {
                        Ok(h) => StreamItem::Hash(h),
                        Err(_) => StreamItem::ReadError {
                            err: DomainError::Validation(format!(
                                "object key basename is not a SHA-256 hex: {name}"
                            )),
                            key: location,
                        },
                    }
                }
                Err(e) => StreamItem::ReadError {
                    key: String::new(),
                    err: DomainError::Invariant(format!("object store list: {e}")),
                },
            });
            let s: BoxStream<'_, StreamItem> = Box::pin(mapped);
            Ok(s)
        })
    }

    fn backend_label(&self) -> &'static str {
        // Coarse label for the scrub metric — see `StoragePort::backend_label`.
        // All object-store backends (S3, GCS, Azure, in-memory) collapse
        // onto the same `object_store` bucket at the scrub-metric level.
        "object_store"
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use object_store::memory::InMemory;
    use tokio::io::AsyncReadExt;

    use super::*;

    fn storage() -> ObjectStoreStorage {
        ObjectStoreStorage::new(
            Arc::new(InMemory::new()),
            crate::metrics::values::BACKEND_MEMORY,
        )
    }

    async fn put_bytes(s: &ObjectStoreStorage, data: &[u8]) -> PutResult {
        let cursor = Box::new(std::io::Cursor::new(data.to_vec()));
        s.put(cursor).await.unwrap()
    }

    async fn get_bytes(s: &ObjectStoreStorage, hash: &ContentHash) -> Vec<u8> {
        let mut reader = s.get(hash).await.unwrap();
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        buf
    }

    const HELLO_WORLD_SHA256: &str =
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    #[tokio::test]
    async fn put_returns_correct_hash_for_known_content() {
        let s = storage();
        let result = put_bytes(&s, b"hello world").await;
        assert_eq!(result.hash.as_ref(), HELLO_WORLD_SHA256);
        assert_eq!(result.size_bytes, 11);
    }

    #[tokio::test]
    async fn put_then_get_roundtrips() {
        let s = storage();
        let data = b"round-trip test payload with some variety \x00\xff";
        let result = put_bytes(&s, data).await;
        assert_eq!(result.size_bytes, data.len() as u64);
        let retrieved = get_bytes(&s, &result.hash).await;
        assert_eq!(retrieved, data);
    }

    #[tokio::test]
    async fn put_is_idempotent() {
        let s = storage();
        let r1 = put_bytes(&s, b"hello world").await;
        let r2 = put_bytes(&s, b"hello world").await;
        // Hash and size match; `created` distinguishes the fresh write from
        // the dedup.
        assert_eq!(r1.hash, r2.hash);
        assert_eq!(r1.size_bytes, r2.size_bytes);
        assert!(r1.created, "first put must be a fresh write");
        assert!(!r2.created, "second put must be a dedup");
        let retrieved = get_bytes(&s, &r1.hash).await;
        assert_eq!(retrieved, b"hello world");
    }

    #[tokio::test]
    async fn get_missing_hash_returns_not_found() {
        let s = storage();
        let hash: ContentHash = HELLO_WORLD_SHA256.parse().unwrap();
        match s.get(&hash).await {
            Err(DomainError::NotFound {
                entity: "content", ..
            }) => {}
            Err(other) => panic!("expected NotFound, got: {other:?}"),
            Ok(_) => panic!("expected NotFound, got Ok"),
        }
    }

    #[tokio::test]
    async fn exists_true_after_put_false_before() {
        let s = storage();
        let hash: ContentHash = HELLO_WORLD_SHA256.parse().unwrap();

        assert!(!s.exists(&hash).await.unwrap());

        put_bytes(&s, b"hello world").await;

        assert!(s.exists(&hash).await.unwrap());
    }

    /// `size_of` returns the stored byte count after `put`, and
    /// `NotFound` when the hash is absent.
    #[tokio::test]
    async fn size_of_after_put_reports_correct_length() {
        let s = storage();
        let payload: &[u8] = b"hello world";
        let put = put_bytes(&s, payload).await;

        let size = s.size_of(&put.hash).await.unwrap();
        assert_eq!(size, payload.len() as u64);
    }

    #[tokio::test]
    async fn size_of_missing_hash_returns_not_found() {
        let s = storage();
        let hash: ContentHash = HELLO_WORLD_SHA256.parse().unwrap();
        match s.size_of(&hash).await {
            Err(DomainError::NotFound {
                entity: "content", ..
            }) => {}
            Err(other) => panic!("expected NotFound, got: {other:?}"),
            Ok(_) => panic!("expected NotFound, got Ok"),
        }
    }

    /// A blob whose bytes have been modified directly in the backing store
    /// (bypassing the port) must surface as `io::ErrorKind::InvalidData`
    /// when the returned stream is read to EOF (ADR 0003). Mirrors the
    /// filesystem adapter's tamper test.
    #[tokio::test]
    async fn get_stream_errors_when_blob_is_tampered_in_backing_store() {
        // Build the storage using a shared InMemory so the test can
        // tamper through the same handle the adapter reads from.
        let inner: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let s = ObjectStoreStorage::new(inner.clone(), values::BACKEND_MEMORY);
        let r = put_bytes(&s, b"hello world").await;

        // Tamper: overwrite the object at the CAS key with different
        // bytes. This simulates a compromised/misconfigured backend or
        // a direct S3 PUT that bypasses our adapter.
        let cas: object_store::path::Path = cas_path(&r.hash).into();
        inner
            .put(&cas, bytes::Bytes::from_static(b"TAMPERED").into())
            .await
            .unwrap();

        let mut reader = s.get(&r.hash).await.unwrap();
        let mut out = Vec::new();
        let err = reader.read_to_end(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains(HELLO_WORLD_SHA256),
            "error should name expected hash, got: {err}"
        );
    }

    #[tokio::test]
    async fn put_empty_content() {
        let s = storage();
        let result = put_bytes(&s, b"").await;
        assert_eq!(
            result.hash.as_ref(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(result.size_bytes, 0);
        let retrieved = get_bytes(&s, &result.hash).await;
        assert!(retrieved.is_empty());
    }

    // ----------------------------------------------------------------------
    // get_range contract suite
    // ----------------------------------------------------------------------

    /// Run the generic `StoragePort::get_range` contract suite against
    /// `ObjectStoreStorage` backed by `InMemory`. The in-memory
    /// object_store is the closest "in-memory adapter" we have under
    /// `hort-adapters-storage` and exercises the streaming-slice
    /// codepath without filesystem I/O.
    #[tokio::test]
    async fn object_store_get_range_contract() {
        let s: Arc<ObjectStoreStorage> = Arc::new(storage());
        let content = crate::range_contract::fixture_payload();
        let put = s
            .put(Box::new(std::io::Cursor::new(content.clone())))
            .await
            .unwrap();
        crate::range_contract::run_contract(s.clone(), put.hash, &content).await;
    }

    // ----------------------------------------------------------------------
    // Metric emission tests
    // ----------------------------------------------------------------------

    use metrics::SharedString;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshot};
    use metrics_util::{CompositeKey, MetricKind};

    use crate::metrics::{labels, values};

    type MetricEntry = (
        CompositeKey,
        Option<metrics::Unit>,
        Option<SharedString>,
        DebugValue,
    );

    fn capture_async<F, Fut>(f: F) -> Snapshot
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(f());
        });
        snapshotter.snapshot()
    }

    fn find_metric(
        entries: &[MetricEntry],
        kind: MetricKind,
        name: &str,
        expected_labels: &[(&str, &str)],
    ) -> Option<(u64, bool)> {
        for (ck, _, _, dv) in entries {
            if ck.kind() != kind || ck.key().name() != name {
                continue;
            }
            let matches = expected_labels
                .iter()
                .all(|(k, v)| ck.key().labels().any(|l| l.key() == *k && l.value() == *v));
            if !matches {
                continue;
            }
            match dv {
                DebugValue::Counter(n) => return Some((*n, true)),
                DebugValue::Histogram(samples) => {
                    return Some((samples.len() as u64, !samples.is_empty()))
                }
                _ => {}
            }
        }
        None
    }

    fn assert_counter(
        entries: &[MetricEntry],
        name: &str,
        expected_labels: &[(&str, &str)],
        expected_value: u64,
    ) {
        let got = find_metric(entries, MetricKind::Counter, name, expected_labels);
        match got {
            Some((n, _)) => assert_eq!(
                n, expected_value,
                "counter {name} with {expected_labels:?} expected {expected_value}, got {n}"
            ),
            None => {
                let names: Vec<&str> = entries
                    .iter()
                    .map(|(ck, _, _, _)| ck.key().name())
                    .collect();
                panic!("counter {name} with {expected_labels:?} not found; seen: {names:?}")
            }
        }
    }

    fn assert_histogram_has_sample(
        entries: &[MetricEntry],
        name: &str,
        expected_labels: &[(&str, &str)],
    ) {
        let got = find_metric(entries, MetricKind::Histogram, name, expected_labels);
        match got {
            Some((_, has)) => assert!(
                has,
                "histogram {name} with {expected_labels:?} has no samples"
            ),
            None => panic!("histogram {name} with {expected_labels:?} not found"),
        }
    }

    #[test]
    fn os_put_success_emits_memory_backend_label() {
        let snap = capture_async(|| async {
            let s = storage();
            put_bytes(&s, b"hello world").await;
        });
        let entries = snap.into_vec();
        assert_counter(
            &entries,
            "hort_storage_operations_total",
            &[
                (labels::BACKEND, values::BACKEND_MEMORY),
                (labels::OPERATION, values::OPERATION_PUT),
                (labels::RESULT, "success"),
            ],
            1,
        );
        assert_histogram_has_sample(
            &entries,
            "hort_storage_operation_duration_seconds",
            &[
                (labels::BACKEND, values::BACKEND_MEMORY),
                (labels::OPERATION, values::OPERATION_PUT),
            ],
        );
    }

    #[test]
    fn os_put_dedup_emits_dedup_counter() {
        let snap = capture_async(|| async {
            let s = storage();
            put_bytes(&s, b"hello world").await;
            put_bytes(&s, b"hello world").await;
        });
        let entries = snap.into_vec();
        assert_counter(
            &entries,
            "hort_storage_operations_total",
            &[
                (labels::BACKEND, values::BACKEND_MEMORY),
                (labels::OPERATION, values::OPERATION_PUT),
                (labels::RESULT, "success"),
            ],
            2,
        );
        assert_counter(
            &entries,
            "hort_storage_dedup_total",
            &[(labels::BACKEND, values::BACKEND_MEMORY)],
            1,
        );
    }

    #[test]
    fn os_get_success_emits_counter_and_histogram() {
        let snap = capture_async(|| async {
            let s = storage();
            let r = put_bytes(&s, b"hello world").await;
            let _ = get_bytes(&s, &r.hash).await;
        });
        let entries = snap.into_vec();
        assert_counter(
            &entries,
            "hort_storage_operations_total",
            &[
                (labels::BACKEND, values::BACKEND_MEMORY),
                (labels::OPERATION, values::OPERATION_GET),
                (labels::RESULT, "success"),
            ],
            1,
        );
        assert_histogram_has_sample(
            &entries,
            "hort_storage_operation_duration_seconds",
            &[
                (labels::BACKEND, values::BACKEND_MEMORY),
                (labels::OPERATION, values::OPERATION_GET),
            ],
        );
    }

    #[test]
    fn os_get_missing_hash_emits_not_found_result() {
        let snap = capture_async(|| async {
            let s = storage();
            let hash: ContentHash = HELLO_WORLD_SHA256.parse().unwrap();
            let _ = s.get(&hash).await;
        });
        let entries = snap.into_vec();
        assert_counter(
            &entries,
            "hort_storage_operations_total",
            &[
                (labels::BACKEND, values::BACKEND_MEMORY),
                (labels::OPERATION, values::OPERATION_GET),
                (labels::RESULT, "not_found"),
            ],
            1,
        );
    }

    /// Tampered-blob discovery at read time emits
    /// `hort_storage_integrity_failures_total{backend}` for the object-store
    /// adapter as well (ADR 0003). Paired with the filesystem version so
    /// both backends share the integrity observability contract.
    #[test]
    fn os_get_tampered_blob_emits_integrity_failure_counter() {
        let snap = capture_async(|| async {
            let inner: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
            let s = ObjectStoreStorage::new(inner.clone(), values::BACKEND_MEMORY);
            let r = put_bytes(&s, b"hello world").await;
            // Tamper directly via the backing store handle.
            let cas: object_store::path::Path = cas_path(&r.hash).into();
            inner
                .put(&cas, bytes::Bytes::from_static(b"TAMPERED").into())
                .await
                .unwrap();
            let mut reader = s.get(&r.hash).await.unwrap();
            let mut out = Vec::new();
            let _ = reader.read_to_end(&mut out).await;
        });
        let entries = snap.into_vec();
        assert_counter(
            &entries,
            "hort_storage_integrity_failures_total",
            &[(labels::BACKEND, values::BACKEND_MEMORY)],
            1,
        );
    }

    // ----------------------------------------------------------------------
    // list_all walk tests
    // ----------------------------------------------------------------------

    async fn collect_list_all(s: &ObjectStoreStorage) -> Vec<StreamItem> {
        let stream = s.list_all().await.unwrap();
        stream.collect().await
    }

    /// Fresh in-memory backend yields an empty list (no blobs stored
    /// yet). Paired with the filesystem empty-root test; the scrubber
    /// treats both the same way.
    #[tokio::test]
    async fn list_all_empty_store_yields_empty_stream() {
        let s = storage();
        let items = collect_list_all(&s).await;
        assert!(items.is_empty());
    }

    /// After a put, the stored hash appears in `list_all`. Pins the
    /// prefix-listing + key-parsing wiring.
    #[tokio::test]
    async fn list_all_yields_put_hash() {
        let s = storage();
        let r = put_bytes(&s, b"hello world").await;

        let items = collect_list_all(&s).await;
        let hashes: Vec<_> = items
            .iter()
            .filter_map(|it| match it {
                StreamItem::Hash(h) => Some(h.clone()),
                // Object-store backends never emit `ShardTruncated`
                // (flat key listing — no per-shard EINTR/WouldBlock
                // retry surface). Both error variants are dropped from
                // this hash-only filter for symmetry.
                StreamItem::ReadError { .. } | StreamItem::ShardTruncated { .. } => None,
            })
            .collect();
        assert_eq!(hashes, vec![r.hash]);
    }

    /// Multiple puts all show up. Object store enumeration ordering is
    /// unspecified per the trait docstring; sort before comparing.
    #[tokio::test]
    async fn list_all_yields_all_hashes_after_multiple_puts() {
        let s = storage();
        let r1 = put_bytes(&s, b"hello world").await;
        let r2 = put_bytes(&s, b"").await;

        let items = collect_list_all(&s).await;
        let mut hashes: Vec<_> = items
            .iter()
            .filter_map(|it| match it {
                StreamItem::Hash(h) => Some(h.to_string()),
                StreamItem::ReadError { .. } | StreamItem::ShardTruncated { .. } => None,
            })
            .collect();
        hashes.sort();
        let mut expected = vec![r1.hash.to_string(), r2.hash.to_string()];
        expected.sort();
        assert_eq!(hashes, expected);
    }

    /// Object keys under `cas/` whose basename is not a SHA-256 hex
    /// surface as `StreamItem::ReadError` — the walk does not abort.
    /// Plants the bogus key directly via the backing `ObjectStore`
    /// handle to bypass the adapter's `put` contract.
    #[tokio::test]
    async fn list_all_surfaces_non_hash_keys_as_read_error() {
        let inner: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let s = ObjectStoreStorage::new(inner.clone(), values::BACKEND_MEMORY);
        // Legitimate blob.
        let r = put_bytes(&s, b"hello world").await;
        // Bogus key under cas/.
        let bogus: object_store::path::Path = "cas/zz/ww/not-a-sha256".into();
        inner
            .put(&bogus, bytes::Bytes::from_static(b"garbage").into())
            .await
            .unwrap();

        let items = collect_list_all(&s).await;
        let hash_items: Vec<_> = items
            .iter()
            .filter(|it| matches!(it, StreamItem::Hash(_)))
            .collect();
        let read_errors: Vec<_> = items
            .iter()
            .filter(|it| matches!(it, StreamItem::ReadError { .. }))
            .collect();
        assert_eq!(hash_items.len(), 1, "expected 1 Hash for real blob");
        assert_eq!(read_errors.len(), 1, "expected 1 ReadError for bogus key");
        // The valid hash round-trips.
        if let StreamItem::Hash(h) = hash_items[0] {
            assert_eq!(*h, r.hash);
        }
    }

    /// `.staging/` keys are NOT visible to `list_all` — the walk only
    /// descends into `cas/`. A `.staging/<uuid>` leaked from a
    /// crashed multipart upload must not pollute the scrub.
    #[tokio::test]
    async fn list_all_ignores_staging_keys() {
        let inner: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let s = ObjectStoreStorage::new(inner.clone(), values::BACKEND_MEMORY);
        // Put a real blob (creates a cas/... key).
        let _ = put_bytes(&s, b"hello world").await;
        // Leak a staging key from a crashed prior upload.
        let leaked: object_store::path::Path = ".staging/leaked".into();
        inner
            .put(&leaked, bytes::Bytes::from_static(b"leaked").into())
            .await
            .unwrap();

        let items = collect_list_all(&s).await;
        let read_errors: Vec<_> = items
            .iter()
            .filter(|it| matches!(it, StreamItem::ReadError { .. }))
            .collect();
        assert!(
            read_errors.is_empty(),
            "staging leak surfaced as scrub ReadError"
        );
    }

    /// The adapter's `backend_label` is the coarse scrub-metric label.
    /// All object-store-family adapters (S3, GCS, Azure, in-memory)
    /// collapse onto `"object_store"` at this level.
    #[test]
    fn object_store_backend_label_is_object_store_coarse() {
        let s = storage();
        assert_eq!(s.backend_label(), "object_store");
    }

    #[test]
    fn os_exists_emits_success_result() {
        let snap = capture_async(|| async {
            let s = storage();
            let hash: ContentHash = HELLO_WORLD_SHA256.parse().unwrap();
            let _ = s.exists(&hash).await;
        });
        let entries = snap.into_vec();
        assert_counter(
            &entries,
            "hort_storage_operations_total",
            &[
                (labels::BACKEND, values::BACKEND_MEMORY),
                (labels::OPERATION, values::OPERATION_EXISTS),
                (labels::RESULT, "success"),
            ],
            1,
        );
        assert_histogram_has_sample(
            &entries,
            "hort_storage_operation_duration_seconds",
            &[
                (labels::BACKEND, values::BACKEND_MEMORY),
                (labels::OPERATION, values::OPERATION_EXISTS),
            ],
        );
    }

    /// Deleting a PRESENT blob increments
    /// `hort_storage_blobs_deleted_bytes_total{backend}` by exactly the
    /// blob's byte size (HEAD'd before the delete; ADR 0020).
    #[test]
    fn os_delete_present_blob_increments_deleted_bytes_by_size() {
        let payload: &[u8] = b"hello world"; // 11 bytes
        let snap = capture_async(|| async {
            let s = storage();
            let put = put_bytes(&s, payload).await;
            s.delete(&put.hash).await.expect("delete present blob");
        });
        let entries = snap.into_vec();
        assert_counter(
            &entries,
            "hort_storage_blobs_deleted_bytes_total",
            &[(labels::BACKEND, values::BACKEND_MEMORY)],
            payload.len() as u64,
        );
    }

    /// Deleting an ABSENT blob (idempotent re-purge / §6 invariant 4)
    /// does NOT increment the bytes counter — no double-count on retry.
    #[test]
    fn os_delete_absent_blob_does_not_increment_deleted_bytes() {
        let snap = capture_async(|| async {
            let s = storage();
            let hash: ContentHash = HELLO_WORLD_SHA256.parse().unwrap();
            let _ = s.delete(&hash).await;
        });
        let entries = snap.into_vec();
        let found = find_metric(
            &entries,
            MetricKind::Counter,
            "hort_storage_blobs_deleted_bytes_total",
            &[(labels::BACKEND, values::BACKEND_MEMORY)],
        );
        assert!(
            found.is_none(),
            "absent-blob delete must NOT emit hort_storage_blobs_deleted_bytes_total"
        );
    }
}
