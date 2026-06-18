//! Adapter-internal workspace setup. The Trivy CLI scans a directory;
//! this module pulls artifact bytes from `StoragePort`, materialises
//! them into a `TempDir`, and hands the directory path back to the
//! adapter. Cleanup is RAII: the returned [`TempDir`] removes its
//! contents on `Drop`, which fires whether the scan succeeded, failed,
//! or panicked.
//!
//! Trivy's filesystem mode rediscovers archives on its own (`.tar.gz`,
//! `.jar`, `.whl`, …), so we do **not** extract here — handing Trivy
//! the raw payload is enough.
//!
//! Bytes are streamed from `StoragePort::get` to the temp
//! file in fixed-size chunks with a running byte count — no
//! full-artifact RAM buffer. The copy is bounded by a configurable
//! `max_artifact_size` cap (from [`TrivyConfig`](crate::TrivyConfig)):
//! if the running total would exceed the cap the copy is aborted and
//! the artifact is rejected *pre-scan* with a `DomainError`, so a
//! multi-GB OCI layer (or a storage stream that never EOFs) can no
//! longer OOM the worker. This mirrors the OOM-safety the CAS `put`
//! path already guarantees.

use std::path::PathBuf;
use std::sync::Arc;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::storage::StoragePort;
use hort_domain::types::ContentHash;
use tempfile::{Builder, TempDir};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Chunk size for the streaming CAS→tempfile copy. 64 KiB is the
/// usual sweet spot for `read`/`write` syscall amortisation without
/// holding a meaningful amount of artifact bytes resident.
const COPY_CHUNK_BYTES: usize = 64 * 1024;

/// Result of [`prepare_workspace`]. Holds the `TempDir` so the caller
/// keeps the workspace alive across the Trivy invocation; drop semantics
/// remove the directory tree.
pub(crate) struct ScanWorkspace {
    /// RAII handle. Drop → directory tree removed.
    pub(crate) tmp: TempDir,
    /// Path to the file we wrote inside `tmp`. Trivy actually scans
    /// `tmp.path()`, but exposing the file path is useful for tests.
    #[allow(dead_code)]
    pub(crate) artifact_path: PathBuf,
}

impl ScanWorkspace {
    /// The path the Trivy CLI gets pointed at — the directory itself,
    /// not the embedded file. Trivy fs scans recursively.
    pub(crate) fn dir(&self) -> &std::path::Path {
        self.tmp.path()
    }
}

/// Build a fresh workspace for one scan: pull the artifact bytes via
/// `StoragePort::get`, **stream** them into a temp file under a fresh
/// `TempDir` (bounded by `max_artifact_size`), and return the
/// [`ScanWorkspace`]. Equivalent to
/// [`prepare_workspace_with_cap`]; the adapter calls this with the
/// cap from its [`TrivyConfig`](crate::TrivyConfig).
///
/// The file inside the workspace is named `<hash>.bin`. Trivy's
/// filesystem mode does not care about the extension — it sniffs the
/// content — so a stable, harmless name is fine.
///
/// Errors:
/// - `DomainError::Invariant(...)` for I/O failures inside the temp
///   workspace (`tempfile`, stream read, file write/flush).
/// - `DomainError::Invariant(...)` naming the cap when the artifact
///   would exceed `max_artifact_size` (rejected pre-scan; the
///   partially-written temp file is dropped with the `TempDir`).
/// - Whatever `StoragePort::get(...)` returns is propagated as-is.
pub(crate) async fn prepare_workspace(
    storage: &Arc<dyn StoragePort>,
    content_hash: &ContentHash,
    max_artifact_size: u64,
) -> DomainResult<ScanWorkspace> {
    prepare_workspace_with_cap(storage, content_hash, max_artifact_size).await
}

/// Streaming, size-capped CAS→tempfile copy. Split out
/// under an explicit name so unit tests can drive the cap behaviour
/// directly without constructing a full adapter.
///
/// The copy reads the storage stream in [`COPY_CHUNK_BYTES`] chunks
/// and maintains a running `written` total. The cap check is
/// `written + chunk_len > max_artifact_size` *before* the chunk is
/// written, so a stream whose length is *exactly* the cap succeeds
/// (the next `read` yields EOF, not an over-cap chunk) while a stream
/// that produces even one byte beyond the cap is rejected — this is
/// what distinguishes "hit the cap" from a legitimate at-cap EOF.
pub(crate) async fn prepare_workspace_with_cap(
    storage: &Arc<dyn StoragePort>,
    content_hash: &ContentHash,
    max_artifact_size: u64,
) -> DomainResult<ScanWorkspace> {
    let tmp = Builder::new()
        .prefix("hort-scan-trivy-")
        .tempdir()
        .map_err(|e| {
            DomainError::Invariant(format!(
                "trivy adapter: failed to create temp workspace: {e}"
            ))
        })?;

    let artifact_path = tmp.path().join(format!("{}.bin", content_hash.as_ref()));

    let mut reader = storage.get(content_hash).await?;
    let mut file = tokio::fs::File::create(&artifact_path).await.map_err(|e| {
        DomainError::Invariant(format!(
            "trivy adapter: failed to create artifact file: {e}"
        ))
    })?;

    // Bounded streaming copy: fixed-size chunks, running byte count,
    // no full-artifact RAM buffer. `buf` is reused across iterations
    // so resident memory is O(COPY_CHUNK_BYTES), not O(artifact size).
    let mut buf = vec![0u8; COPY_CHUNK_BYTES];
    let mut written: u64 = 0;
    loop {
        let n = reader.read(&mut buf).await.map_err(|e| {
            DomainError::Invariant(format!("trivy adapter: failed to read storage stream: {e}"))
        })?;
        if n == 0 {
            // EOF — the at-cap artifact lands here without ever
            // tripping the over-cap branch below.
            break;
        }
        // Cap check *before* writing this chunk. `written + n` cannot
        // wrap: `written <= max_artifact_size` holds on entry and `n`
        // fits in `usize`/`u64`.
        if written + (n as u64) > max_artifact_size {
            // RAII: `tmp` (and the partial file inside it) is removed
            // when it drops at function exit on this error path.
            tracing::warn!(
                scanner = "trivy",
                content_hash = %content_hash,
                max_artifact_size,
                "trivy adapter: artifact exceeds max-artifact-size cap; rejecting pre-scan"
            );
            return Err(DomainError::Invariant(format!(
                "trivy adapter: artifact exceeds max-artifact-size cap \
                 ({max_artifact_size} bytes); rejected pre-scan to protect the worker"
            )));
        }
        file.write_all(&buf[..n]).await.map_err(|e| {
            DomainError::Invariant(format!(
                "trivy adapter: failed to write artifact bytes: {e}"
            ))
        })?;
        written += n as u64;
    }

    file.flush().await.map_err(|e| {
        DomainError::Invariant(format!("trivy adapter: failed to flush artifact file: {e}"))
    })?;

    Ok(ScanWorkspace { tmp, artifact_path })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;

    use hort_domain::ports::storage::{PutResult, StoragePort};
    use hort_domain::ports::BoxFuture;
    use hort_domain::types::{ByteRange, ContentHash};
    use tokio::io::AsyncRead;

    /// In-memory storage stub returning a fixed byte slice for `get`.
    /// Other methods are unused by `prepare_workspace`.
    struct StubStorage {
        bytes: Vec<u8>,
    }

    impl StoragePort for StubStorage {
        fn put(
            &self,
            _stream: Box<dyn AsyncRead + Send + Unpin>,
        ) -> BoxFuture<'_, DomainResult<PutResult>> {
            Box::pin(async { unreachable!("test stub") })
        }
        fn get(
            &self,
            _hash: &ContentHash,
        ) -> BoxFuture<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>> {
            let cursor = Cursor::new(self.bytes.clone());
            Box::pin(async move {
                let r: Box<dyn AsyncRead + Send + Unpin> = Box::new(cursor);
                Ok(r)
            })
        }
        fn get_range(
            &self,
            _hash: &ContentHash,
            _range: ByteRange,
        ) -> BoxFuture<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>> {
            Box::pin(async { unreachable!("test stub") })
        }
        fn exists(&self, _hash: &ContentHash) -> BoxFuture<'_, DomainResult<bool>> {
            Box::pin(async { unreachable!("test stub") })
        }
        fn size_of(&self, _hash: &ContentHash) -> BoxFuture<'_, DomainResult<u64>> {
            Box::pin(async { unreachable!("test stub") })
        }
    }

    fn sample_hash() -> ContentHash {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .unwrap()
    }

    #[tokio::test]
    async fn prepare_workspace_writes_payload_into_temp_dir() {
        let storage: Arc<dyn StoragePort> = Arc::new(StubStorage {
            bytes: b"trivy scan target bytes".to_vec(),
        });
        let hash = sample_hash();
        let ws = prepare_workspace(&storage, &hash, u64::MAX)
            .await
            .expect("prepare");

        // The workspace dir exists, contains exactly one file, and that
        // file's bytes match the stub.
        let dir = ws.dir().to_owned();
        assert!(dir.exists());
        let written = tokio::fs::read(&ws.artifact_path).await.unwrap();
        assert_eq!(written, b"trivy scan target bytes");
    }

    #[tokio::test]
    async fn prepare_workspace_rejects_oversize_artifact_before_scan() {
        // Stream is 64 bytes; cap is 16 → must reject pre-scan with a
        // `trivy adapter:` invariant error naming the cap, and must NOT
        // leave a full-size temp file behind.
        let storage: Arc<dyn StoragePort> = Arc::new(StubStorage {
            bytes: vec![0xAB; 64],
        });
        let hash = sample_hash();
        let result = prepare_workspace_with_cap(&storage, &hash, 16).await;
        match result {
            Err(DomainError::Invariant(msg)) => {
                assert!(msg.contains("trivy adapter"), "{msg}");
                assert!(
                    msg.contains("16") && msg.to_lowercase().contains("exceed"),
                    "error must name the cap and that it was exceeded: {msg}"
                );
            }
            Err(other) => panic!("expected Invariant error, got {other:?}"),
            Ok(_) => panic!("oversize artifact must be rejected, got Ok(ScanWorkspace)"),
        }
    }

    #[tokio::test]
    async fn prepare_workspace_accepts_artifact_exactly_at_cap_and_roundtrips_bytes() {
        // A stream whose length is *exactly* the cap must succeed (the
        // cap is "reject when it would exceed", not "reject at cap"),
        // and the streamed bytes must round-trip byte-for-byte (proves
        // the streaming copy is correct, not just non-buffering).
        let payload = b"exactly-thirty-two-bytes-here!!!".to_vec();
        assert_eq!(payload.len(), 32);
        let storage: Arc<dyn StoragePort> = Arc::new(StubStorage {
            bytes: payload.clone(),
        });
        let hash = sample_hash();
        let ws = prepare_workspace_with_cap(&storage, &hash, 32)
            .await
            .expect("at-cap artifact must be accepted");
        let written = tokio::fs::read(&ws.artifact_path).await.unwrap();
        assert_eq!(written, payload, "streamed bytes must round-trip exactly");
    }

    #[tokio::test]
    async fn workspace_drops_remove_temp_dir() {
        let storage: Arc<dyn StoragePort> = Arc::new(StubStorage {
            bytes: vec![1, 2, 3],
        });
        let hash = sample_hash();
        let dir_path: PathBuf;
        {
            let ws = prepare_workspace(&storage, &hash, u64::MAX)
                .await
                .expect("prepare");
            dir_path = ws.dir().to_path_buf();
            assert!(dir_path.exists());
        }
        // After ws drops, the temp dir is gone.
        assert!(
            !dir_path.exists(),
            "TempDir drop should remove the workspace at {}",
            dir_path.display()
        );
    }
}
