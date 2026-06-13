//! Consumer-side projection over a cached upstream body (ADR 0026).
//!
//! Opens the file at `CachedBodyHandle::path` and runs the supplied
//! `MetadataProjector` under `tokio::task::spawn_blocking`. Single
//! sync/async bridge for every consumer — keeps `spawn_blocking` from
//! being scattered across npm / PyPI / cargo / OCI crates.
//!
//! The metadata path (npm / PyPI / cargo sparse index) streams through
//! this module: each format runs its body method via [`run_handler_body`]
//! or its per-format projector via [`fetch_and_project`], never buffering
//! the upstream body into a `Vec<u8>` (there is deliberately no
//! `metadata_body_bytes`-style helper recovering that shape — the
//! `streaming_metadata_port` guard test pins this).
//!
//! The OCI manifest path holds the same line: there is no
//! `manifest_body_bytes` helper — the manifest pull-through
//! streams the fetch tempfile straight into CAS via
//! `IngestUseCase::ingest_verified`, and the tag-pull leg broadcasts the
//! resolved content hash (not the manifest bytes) through the dedup
//! layer. No upstream-body consumer in this module buffers the whole body.
//!
//! See ADR 0026.

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::metadata_mirror_store::MetadataMirrorStore;
use hort_domain::ports::upstream_proxy::{CachedBodyHandle, MetadataProjector};

/// Write a buffered upstream body to a tempfile and return a
/// [`CachedBodyHandle`] pointing at it. The production path streams the
/// body into the cache layer (`cache.write_streaming`),
/// so this in-memory helper survives only for the `MockUpstreamProxy` in
/// `crate::use_cases::test_support`, which materialises fixture bodies up
/// front and needs them in the production outcome shape.
///
/// Sync because the bytes are already materialised in memory. Cleanup of
/// the produced tempfile is the consumer's responsibility (e.g.
/// [`remove_cached_body`]).
pub fn cache_handle_from_bytes(bytes: &[u8], key: String) -> DomainResult<CachedBodyHandle> {
    use std::io::Write;
    let mut tf = tempfile::Builder::new()
        .prefix("hort-upstream-")
        .tempfile()
        .map_err(|e| DomainError::Invariant(format!("create upstream temp file: {e}")))?;
    tf.write_all(bytes)
        .map_err(|e| DomainError::Invariant(format!("write upstream temp file: {e}")))?;
    let byte_length = bytes.len() as u64;
    let (_, path) = tf
        .keep()
        .map_err(|e| DomainError::Invariant(format!("persist upstream temp file: {e}")))?;
    Ok(CachedBodyHandle {
        key,
        path,
        fetched_at: chrono::Utc::now(),
        byte_length,
    })
}

/// Open the cached body file and run the projector on a blocking
/// thread. Returns the typed projection.
///
/// The blocking-thread bridge is mandatory because every projector is
/// synchronous (`R: std::io::Read`) — the sync trait lets per-format
/// projectors use `serde_json::Deserializer::from_reader` directly
/// without smearing async machinery across the parser. Spawning here
/// keeps the bridge in one place so format crates don't reach for
/// `spawn_blocking` themselves.
///
/// **Error mapping.** File-open and projector failures surface as
/// [`DomainError::Validation`] (operator-actionable — the file path is
/// in the message). A panic in the blocking task surfaces as
/// [`DomainError::Invariant`] (should-never-happen; the projector is
/// expected to return `Err` rather than panic on bad input).
pub async fn project_cached<P: MetadataProjector>(
    handle: &CachedBodyHandle,
    projector: P,
) -> DomainResult<P::Projection> {
    let path = handle.path.clone();
    tokio::task::spawn_blocking(move || {
        let file = std::fs::File::open(&path).map_err(|e| {
            DomainError::Validation(format!(
                "failed to open cached body at {}: {e}",
                path.display()
            ))
        })?;
        projector.project(std::io::BufReader::new(file))
    })
    .await
    .map_err(|e| DomainError::Invariant(format!("project_cached task panicked: {e}")))?
}

/// Run a synchronous `FormatHandler` body method against
/// a cached upstream body on a blocking thread.
///
/// The `FormatHandler` body methods (`parse_upstream_checksum`,
/// `extract_upstream_versions`, `extract_dependency_specs`) take a
/// `&mut dyn std::io::Read` and are synchronous, so the prefetch handlers
/// open `handle.path` and run them via `tokio::task::spawn_blocking` —
/// streaming the tempfile through the port instead of buffering the body
/// into a `Vec<u8>`. `op` is `FnOnce(&mut dyn Read)` so the caller closes
/// over the `Arc<dyn FormatHandler>` (which is `Send + Sync`) and the
/// coords, returning the method's typed result.
///
/// Does NOT delete the tempfile — the caller owns the cache-handle
/// lifecycle (it may run several ops against one handle, e.g. PyPI's
/// per-distribution checksum fan-out). Use [`remove_cached_body`] when
/// the handle is no longer needed.
///
/// **Error mapping** mirrors [`project_cached`]: file-open and method
/// failures surface as the method's own `DomainError`; a panic in the
/// blocking task surfaces as [`DomainError::Invariant`].
pub async fn run_handler_body<T, F>(handle: &CachedBodyHandle, op: F) -> DomainResult<T>
where
    T: Send + 'static,
    F: FnOnce(&mut dyn std::io::Read) -> DomainResult<T> + Send + 'static,
{
    let path = handle.path.clone();
    tokio::task::spawn_blocking(move || {
        let file = std::fs::File::open(&path).map_err(|e| {
            DomainError::Validation(format!(
                "failed to open cached body at {}: {e}",
                path.display()
            ))
        })?;
        let mut reader = std::io::BufReader::new(file);
        op(&mut reader)
    })
    .await
    .map_err(|e| DomainError::Invariant(format!("run_handler_body task panicked: {e}")))?
}

/// Best-effort removal of a cached-body tempfile — a failure logs at
/// `debug` and does not propagate (the cache-layer lifecycle
/// bounds any leakage).
pub async fn remove_cached_body(handle: &CachedBodyHandle) {
    if let Err(e) = tokio::fs::remove_file(&handle.path).await {
        tracing::debug!(
            path = %handle.path.display(),
            error = %e,
            "remove_cached_body: best-effort temp-file cleanup failed"
        );
    }
}

/// Two-pass, bounded-memory metadata ingest (ADR 0026).
///
/// **PASS 1** — [`project_cached`] streams the cached upstream body
/// through `projector` (validate + project). An `Err` here propagates
/// immediately and **PASS 2 NEVER runs** — validate-before-commit,
/// fail-closed: a malformed body never reaches the mirror.
///
/// **PASS 2** — re-open `handle.path` and stream the raw body into
/// `mirror.put(mirror_key, ...)` (valid bodies only). No full-body
/// `Vec`: the body flows file → `tokio::io::copy` → mirror.
///
/// Returns the typed `P::Projection`. Does NOT delete the tempfile —
/// the caller owns the cache-handle lifecycle (use [`remove_cached_body`]
/// when the handle is no longer needed).
///
/// Observability: `#[instrument]` carries `mirror_key` only —
/// never the body bytes — and is deliberately WITHOUT `err` (a malformed
/// upstream body is a validation *outcome*, not an ERROR-level event).
/// The PASS-1 reject is reported at `info`; a PASS-2 mirror-put failure
/// at `warn`.
#[tracing::instrument(skip(handle, projector, mirror), fields(mirror_key = %mirror_key))]
pub async fn fetch_and_project<P: MetadataProjector>(
    handle: &CachedBodyHandle,
    projector: P,
    mirror: &dyn MetadataMirrorStore,
    mirror_key: &str,
) -> DomainResult<P::Projection> {
    // PASS 1 — streaming validate/project over the tempfile. An Err here
    // (malformed body / per-value cap trip) means nothing is committed:
    // PASS 2 below is never reached, so the mirror stays untouched.
    let projection = match project_cached(handle, projector).await {
        Ok(p) => p,
        Err(e) => {
            tracing::info!("metadata rejected — invalid upstream body");
            return Err(e);
        }
    };

    // PASS 2 — stream the raw body to the mirror (valid bodies only).
    let file = tokio::fs::File::open(&handle.path).await.map_err(|e| {
        DomainError::Invariant(format!(
            "mirror source open at {}: {e}",
            handle.path.display()
        ))
    })?;
    if let Err(e) = mirror.put(mirror_key, Box::new(file)).await {
        tracing::warn!(error = %e, "metadata mirror put failed");
        return Err(e);
    }

    Ok(projection)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use hort_domain::ports::upstream_proxy::IdentityProjector;
    use std::io::Write;

    fn write_temp(bytes: &[u8]) -> CachedBodyHandle {
        let mut tmp = tempfile::NamedTempFile::new().expect("create temp");
        tmp.write_all(bytes).expect("write");
        let (_, path) = tmp.keep().expect("keep");
        CachedBodyHandle {
            key: "test".into(),
            path,
            fetched_at: Utc::now(),
            byte_length: bytes.len() as u64,
        }
    }

    #[tokio::test]
    async fn identity_projector_returns_body_bytes() {
        let handle = write_temp(b"hello world");
        let bytes = project_cached(&handle, IdentityProjector)
            .await
            .expect("project");
        assert_eq!(bytes, b"hello world");
        // Test artefact cleanup; in production the cache layer owns
        // lifetime (Item 2 / Item 7).
        std::fs::remove_file(&handle.path).ok();
    }

    #[tokio::test]
    async fn missing_path_surfaces_as_validation_error() {
        let handle = CachedBodyHandle {
            key: "test".into(),
            path: std::path::PathBuf::from("/nonexistent/hort-init57-test/missing.bin"),
            fetched_at: Utc::now(),
            byte_length: 0,
        };
        let err = project_cached(&handle, IdentityProjector)
            .await
            .expect_err("missing path → Validation");
        assert!(
            matches!(err, DomainError::Validation(_)),
            "expected Validation, got {err:?}"
        );
    }

    #[tokio::test]
    async fn empty_body_round_trips() {
        let handle = write_temp(b"");
        let bytes = project_cached(&handle, IdentityProjector)
            .await
            .expect("project");
        assert!(bytes.is_empty());
        std::fs::remove_file(&handle.path).ok();
    }
}

#[cfg(test)]
mod fetch_and_project_tests {
    use super::*;
    use chrono::Utc;
    use futures::future::BoxFuture;
    use hort_domain::ports::metadata_mirror_store::MetadataMirrorStore;
    use std::io::Write;
    use std::sync::Mutex;
    use tokio::io::{AsyncRead, AsyncReadExt};

    /// Test projector: returns the body length, but rejects any body
    /// starting with `b"BAD"` (the malformed-input stand-in). Exercises
    /// PASS 1 success (returns the projection) and PASS 1 failure (the
    /// fail-closed reject path that must skip PASS 2).
    #[derive(Clone, Copy)]
    struct LenProjector;

    impl MetadataProjector for LenProjector {
        type Projection = usize;
        fn project<R: std::io::Read>(self, mut r: R) -> DomainResult<usize> {
            let mut b = Vec::new();
            r.read_to_end(&mut b)
                .map_err(|e| DomainError::Validation(e.to_string()))?;
            if b.starts_with(b"BAD") {
                return Err(DomainError::Validation("bad".into()));
            }
            Ok(b.len())
        }
    }

    /// In-memory mirror that records every `put` (key + bytes) so the
    /// tests can assert PASS 2 ran exactly once on the valid path and
    /// NEVER on the malformed path.
    #[derive(Default)]
    struct RecordingMirror {
        puts: Mutex<Vec<(String, Vec<u8>)>>,
    }

    impl MetadataMirrorStore for RecordingMirror {
        fn put(
            &self,
            key: &str,
            mut body: Box<dyn AsyncRead + Send + Unpin>,
        ) -> BoxFuture<'_, DomainResult<()>> {
            let key = key.to_string();
            Box::pin(async move {
                let mut buf = Vec::new();
                body.read_to_end(&mut buf)
                    .await
                    .map_err(|e| DomainError::Invariant(e.to_string()))?;
                self.puts.lock().unwrap().push((key, buf));
                Ok(())
            })
        }

        fn get(
            &self,
            _key: &str,
        ) -> BoxFuture<'_, DomainResult<Option<Box<dyn AsyncRead + Send + Unpin>>>> {
            Box::pin(async { Ok(None) })
        }

        fn delete(&self, _key: &str) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    /// Mirror whose `put` always fails — exercises the PASS-2
    /// mirror-put-failure branch (the `tracing::warn!` path).
    #[derive(Default)]
    struct FailingPutMirror;

    impl MetadataMirrorStore for FailingPutMirror {
        fn put(
            &self,
            _key: &str,
            _body: Box<dyn AsyncRead + Send + Unpin>,
        ) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Err(DomainError::Invariant("mirror down".into())) })
        }

        fn get(
            &self,
            _key: &str,
        ) -> BoxFuture<'_, DomainResult<Option<Box<dyn AsyncRead + Send + Unpin>>>> {
            Box::pin(async { Ok(None) })
        }

        fn delete(&self, _key: &str) -> BoxFuture<'_, DomainResult<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    fn write_handle(bytes: &[u8]) -> CachedBodyHandle {
        let mut tmp = tempfile::NamedTempFile::new().expect("create temp");
        tmp.write_all(bytes).expect("write");
        let (_, path) = tmp.keep().expect("keep");
        CachedBodyHandle {
            key: "test".into(),
            path,
            fetched_at: Utc::now(),
            byte_length: bytes.len() as u64,
        }
    }

    #[tokio::test]
    async fn valid_body_projects_and_mirrors() {
        let handle = write_handle(b"hello");
        let mirror = RecordingMirror::default();

        let projection = fetch_and_project(&handle, LenProjector, &mirror, "meta-mirror/t/m/p")
            .await
            .expect("valid body projects");

        // PASS 1 returned the projection.
        assert_eq!(projection, 5);
        // PASS 2 ran exactly once, with the raw bytes under the key.
        let puts = mirror.puts.lock().unwrap();
        assert_eq!(puts.len(), 1, "mirror.put must be called exactly once");
        assert_eq!(puts[0].0, "meta-mirror/t/m/p");
        assert_eq!(puts[0].1, b"hello");

        std::fs::remove_file(&handle.path).ok();
    }

    #[tokio::test]
    async fn malformed_body_returns_err_and_does_not_mirror() {
        let handle = write_handle(b"BAD body bytes");
        let mirror = RecordingMirror::default();

        let err = fetch_and_project(&handle, LenProjector, &mirror, "meta-mirror/t/m/p")
            .await
            .expect_err("malformed body must error");

        // Fail-closed: PASS 1 rejected, PASS 2 NEVER ran.
        assert!(
            matches!(err, DomainError::Validation(_)),
            "expected Validation, got {err:?}"
        );
        assert!(
            mirror.puts.lock().unwrap().is_empty(),
            "mirror.put must NOT be called when PASS 1 rejects"
        );

        std::fs::remove_file(&handle.path).ok();
    }

    /// Projector that succeeds (PASS 1 returns `Ok`) but deletes the
    /// source file as a side effect — so PASS 2's `File::open` then fails.
    /// This is the only deterministic way to reach the PASS-2 open-error
    /// branch (PASS 1 must have succeeded for control to get there).
    #[derive(Clone)]
    struct DeleteAfterReadProjector {
        path: std::path::PathBuf,
    }

    impl MetadataProjector for DeleteAfterReadProjector {
        type Projection = usize;
        fn project<R: std::io::Read>(self, mut r: R) -> DomainResult<usize> {
            let mut b = Vec::new();
            r.read_to_end(&mut b)
                .map_err(|e| DomainError::Validation(e.to_string()))?;
            // Drop the source between PASS 1 and PASS 2.
            std::fs::remove_file(&self.path).ok();
            Ok(b.len())
        }
    }

    #[tokio::test]
    async fn pass2_mirror_put_failure_propagates() {
        // PASS 1 succeeds, PASS 2's mirror.put fails → the error
        // propagates (validate-before-commit already passed, but the
        // commit itself can still fail; the warn path).
        let handle = write_handle(b"hello");
        let mirror = FailingPutMirror;

        let err = fetch_and_project(&handle, LenProjector, &mirror, "meta-mirror/t/m/p")
            .await
            .expect_err("mirror put failure must propagate");

        assert!(
            matches!(err, DomainError::Invariant(_)),
            "expected the mirror's Invariant error, got {err:?}"
        );

        std::fs::remove_file(&handle.path).ok();
    }

    #[tokio::test]
    async fn pass2_open_error_surfaces_as_invariant_and_does_not_mirror() {
        // PASS 1 succeeds, then the source disappears before PASS 2 →
        // the reachable PASS-2 source-open I/O error (DomainError::Invariant).
        let handle = write_handle(b"hi");
        let mirror = RecordingMirror::default();
        let projector = DeleteAfterReadProjector {
            path: handle.path.clone(),
        };

        let err = fetch_and_project(&handle, projector, &mirror, "meta-mirror/t/m/p")
            .await
            .expect_err("missing source at PASS 2 must error");

        // PASS 2's File::open failed → Invariant; mirror was never written.
        assert!(
            matches!(err, DomainError::Invariant(_)),
            "expected Invariant from PASS-2 open, got {err:?}"
        );
        assert!(
            mirror.puts.lock().unwrap().is_empty(),
            "mirror.put must NOT be called when the PASS-2 source open fails"
        );
    }
}
