use std::path::{Path, PathBuf};

use futures::stream::{self, BoxStream};
use sha2::{Digest, Sha256};
use tokio::fs;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::storage::{PutResult, StoragePort, StreamItem};
use hort_domain::ports::BoxFuture;
use hort_domain::types::{ByteRange, ContentHash};

use crate::cas::cas_path;
use crate::integrity::VerifyingReader;
use crate::metrics::{emit_integrity_failure, values, MetricGuard};

/// Buffer size for streaming reads — 64 KB per concurrent transfer.
const CHUNK_SIZE: usize = 64 * 1024;

/// Sub-directory under the CAS root where in-flight uploads are staged.
/// Kept within the same filesystem as the CAS root so the final `rename`
/// is atomic.
const STAGING_DIR: &str = ".staging";

/// Return `Some(mode)` if any of the world-permission bits are set on
/// `mode` (i.e. `mode & 0o007 != 0`), `None` otherwise.
///
/// Pure function — extracted so the branch is unit-testable without having
/// to capture `tracing` events.
#[cfg(unix)]
fn detect_world_readable_bits(mode: u32) -> Option<u32> {
    if mode & 0o007 != 0 {
        Some(mode)
    } else {
        None
    }
}

/// Filesystem-backed content-addressable storage.
///
/// Stores artifacts under a two-level shard directory derived from the
/// SHA-256 content hash: `{root}/cas/{h[0..2]}/{h[2..4]}/{hash}`.
/// Writes are atomic (temp file + rename). Deduplicates on hash match.
pub struct FilesystemStorage {
    root: PathBuf,
    /// Backend label emitted with every metric. Hardcoded for this adapter.
    backend: &'static str,
}

impl FilesystemStorage {
    /// Construct a filesystem CAS adapter rooted at `root`.
    ///
    /// Side-effects:
    /// - Creates `<root>/.staging/` with mode `0o700` on Unix (idempotent;
    ///   existing dirs are re-chmod'd back to `0o700` defensively).
    /// - Emits `tracing::warn!` if `<root>` has any world-permission bits
    ///   set (`mode & 0o007 != 0`). Does NOT fail startup — operators may
    ///   have legitimate reasons (shared filesystem with group/world read).
    ///
    /// Errors during staging-dir setup are logged but not surfaced: the
    /// `put()` hot path tolerates a missing staging dir (it will retry
    /// `create_dir_all` on first use). Failing `new()` would couple
    /// composition-root startup to filesystem state we'd rather observe
    /// at runtime.
    pub fn new(root: PathBuf) -> Self {
        Self::prepare_root(&root);
        Self {
            root,
            backend: values::BACKEND_FILESYSTEM,
        }
    }

    /// Resolve a content hash to an absolute filesystem path.
    fn resolve(&self, hash: &ContentHash) -> PathBuf {
        self.root.join(cas_path(hash))
    }

    /// Path to the staging sub-directory holding in-flight temp files.
    fn staging_dir(&self) -> PathBuf {
        self.root.join(STAGING_DIR)
    }

    /// Unix: ensure `<root>/.staging/` exists with mode `0o700`, and warn
    /// if `<root>` itself is world-readable. Non-Unix fallback: create the
    /// staging dir without mode bits (permission semantics differ on
    /// Windows; the project's primary target is Linux).
    #[cfg(unix)]
    fn prepare_root(root: &Path) {
        use std::os::unix::fs::PermissionsExt;

        let staging = root.join(STAGING_DIR);

        // Create the staging dir if missing. Best-effort: any error is
        // logged but not propagated — `put()` re-runs `create_dir_all`
        // before each upload.
        if let Err(e) = std::fs::create_dir_all(&staging) {
            warn!(
                staging = %staging.display(),
                error = %e,
                "failed to create filesystem CAS staging dir; put() will retry"
            );
        } else {
            // Enforce 0o700 whether we just created it or found it
            // pre-existing at a laxer mode. Chmod is cheap and idempotent.
            match std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o700)) {
                Ok(()) => {
                    info!(
                        root = %root.display(),
                        staging = %staging.display(),
                        "filesystem CAS staging dir ready"
                    );
                }
                Err(chmod_err) => {
                    // Chmod failed. Re-stat and escalate the log level
                    // based on the ACTUAL mode: if the staging dir is
                    // already tight (0o700 or tighter) the chmod was a
                    // redundant no-op and the failure is benign. If the
                    // dir is still group/world-accessible, temp files
                    // land somewhere other processes can read — a real
                    // security hazard that must surface at error! level.
                    match std::fs::metadata(&staging) {
                        Ok(meta) => {
                            let actual = meta.permissions().mode() & 0o777;
                            if actual & 0o077 != 0 {
                                error!(
                                    staging = %staging.display(),
                                    chmod_error = %chmod_err,
                                    actual_mode = format!("{actual:o}"),
                                    "failed to chmod 0o700 on staging dir; \
                                     group/world-accessible bits remain — temp files \
                                     may be readable by other local users"
                                );
                            } else {
                                info!(
                                    root = %root.display(),
                                    staging = %staging.display(),
                                    actual_mode = format!("{actual:o}"),
                                    "filesystem CAS staging dir ready (chmod was redundant)"
                                );
                            }
                        }
                        Err(stat_err) => {
                            error!(
                                staging = %staging.display(),
                                chmod_error = %chmod_err,
                                stat_error = %stat_err,
                                "failed to chmod 0o700 on staging dir and unable to verify actual mode"
                            );
                        }
                    }
                }
            }
        }

        // World-readable root check. We stat the root AFTER creating
        // `.staging/` so `create_dir_all` can mkdir the root if missing
        // (test fixtures rely on that).
        match std::fs::metadata(root) {
            Ok(meta) => {
                let mode = meta.permissions().mode() & 0o777;
                if let Some(offending) = detect_world_readable_bits(mode) {
                    warn!(
                        root = %root.display(),
                        mode = format!("{offending:o}"),
                        "filesystem CAS root has world-readable bits; consider chmod 0700 or 0750"
                    );
                }
            }
            Err(e) => {
                warn!(
                    root = %root.display(),
                    error = %e,
                    "failed to stat filesystem CAS root; skipping world-readable check"
                );
            }
        }
    }

    /// Non-Unix fallback: permission bits do not map 1:1 on Windows, and
    /// the world-readable check is meaningless there. We still create the
    /// staging sub-dir so the rest of the adapter's code path is uniform.
    #[cfg(not(unix))]
    fn prepare_root(root: &Path) {
        let staging = root.join(STAGING_DIR);
        if let Err(e) = std::fs::create_dir_all(&staging) {
            warn!(
                staging = %staging.display(),
                error = %e,
                "failed to create filesystem CAS staging dir; put() will retry"
            );
        } else {
            info!(
                root = %root.display(),
                staging = %staging.display(),
                "filesystem CAS staging dir ready (non-Unix; permission check skipped)"
            );
        }
    }
}

impl StoragePort for FilesystemStorage {
    fn put(
        &self,
        mut stream: Box<dyn AsyncRead + Send + Unpin>,
    ) -> BoxFuture<'_, DomainResult<PutResult>> {
        let backend = self.backend;
        Box::pin(async move {
            let mut guard = MetricGuard::new(backend, values::OPERATION_PUT);
            // Temp files live under `<root>/.staging/` — same filesystem as
            // the final CAS key by construction, so the terminal `rename`
            // below stays atomic.
            let staging = self.staging_dir();
            ensure_dir(&staging, &self.root).await?;
            let temp_name = format!(".tmp.{}", Uuid::new_v4());
            let temp_path = staging.join(&temp_name);

            // Pin the temp file to 0o600 atomically with creation
            // (ADR 0026 + `docs/architecture/security.md`). Unix-rename
            // below preserves the inode + its mode bits, so the final
            // blob at the CAS key inherits 0o600 without a follow-up
            // chmod. On non-Unix the mode is silently ignored — Windows
            // ACL semantics differ and the project's primary target
            // is Linux.
            let mut open_opts = fs::OpenOptions::new();
            open_opts.create(true).write(true).truncate(true);
            #[cfg(unix)]
            {
                open_opts.mode(0o600);
            }
            let mut file = open_opts.open(&temp_path).await.map_err(|e| {
                warn!(path = %temp_path.display(), error = %e, "failed to create temp file");
                DomainError::Invariant(format!("storage write failed: {e}"))
            })?;

            let mut hasher = Sha256::new();
            let mut buf = vec![0u8; CHUNK_SIZE];
            let mut total_bytes: u64 = 0;

            // Any error past this point must clean up the staging temp
            // file — otherwise a long string of failed uploads leaks
            // `.tmp.<uuid>` entries under `.staging/` forever.
            let result: DomainResult<(ContentHash, u64)> = async {
                loop {
                    let n = stream.read(&mut buf).await.map_err(|e| {
                        warn!(error = %e, "failed to read from input stream");
                        DomainError::Invariant(format!("storage read failed: {e}"))
                    })?;
                    if n == 0 {
                        break;
                    }
                    total_bytes += n as u64;
                    hasher.update(&buf[..n]);
                    file.write_all(&buf[..n]).await.map_err(|e| {
                        warn!(path = %temp_path.display(), error = %e, "failed to write chunk");
                        DomainError::Invariant(format!("storage write failed: {e}"))
                    })?;
                }

                // Flush to disk before rename for crash safety.
                file.sync_all().await.map_err(|e| {
                    warn!(path = %temp_path.display(), error = %e, "sync_all failed");
                    DomainError::Invariant(format!("storage sync failed: {e}"))
                })?;

                let hash_hex = format!("{:x}", hasher.finalize());
                let hash: ContentHash = hash_hex.parse().map_err(|e| {
                    DomainError::Invariant(format!("SHA-256 produced invalid hex: {e}"))
                })?;
                Ok((hash, total_bytes))
            }
            .await;

            drop(file);

            let (hash, total_bytes) = match result {
                Ok(v) => v,
                Err(e) => {
                    // Best-effort: remove the half-written temp file so it
                    // doesn't accumulate in `.staging/`.
                    let _ = fs::remove_file(&temp_path).await;
                    return Err(e);
                }
            };

            let final_path = self.resolve(&hash);

            if final_path.exists() {
                // Deduplicate: identical content already stored.
                debug!(%hash, "deduplicated");
                let _ = fs::remove_file(&temp_path).await;
                guard.finish_success();
                guard.mark_dedup();
                return Ok(PutResult {
                    hash,
                    size_bytes: total_bytes,
                    created: false,
                });
            }

            // Ensure shard directory exists.
            if let Some(parent) = final_path.parent() {
                ensure_dir(parent, &self.root).await?;
            }

            fs::rename(&temp_path, &final_path).await.map_err(|e| {
                // Rename failed — clean up the temp file so it doesn't
                // leak (the final destination may or may not exist).
                let leaked = temp_path.clone();
                tokio::spawn(async move {
                    let _ = fs::remove_file(&leaked).await;
                });
                warn!(
                    from = %temp_path.display(),
                    to = %final_path.display(),
                    error = %e,
                    "atomic rename failed"
                );
                DomainError::Invariant(format!("storage rename failed: {e}"))
            })?;

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
        let path = self.resolve(hash);
        let hash_display = hash.to_string();
        let expected_hash = hash.clone();
        Box::pin(async move {
            let mut guard = MetricGuard::new(backend, values::OPERATION_GET);
            let file = match fs::File::open(&path).await {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    debug!(hash = %hash_display, "not found");
                    guard.finish_not_found();
                    return Err(DomainError::NotFound {
                        entity: "content",
                        id: hash_display.clone(),
                    });
                }
                Err(e) => {
                    warn!(hash = %hash_display, error = %e, "failed to open file");
                    return Err(DomainError::Invariant(format!("storage read failed: {e}")));
                }
            };
            debug!(hash = %hash_display, "retrieved");
            guard.finish_success();
            // Wrap the file reader in a streaming SHA-256 verifier
            // (ADR 0003). Bytes hash as they flow; at EOF a mismatch
            // surfaces as `io::ErrorKind::InvalidData`. The `get` call
            // itself still records `result="success"` — verification
            // outcome is the read's concern, not the lookup's;
            // `hort_storage_integrity_failures_total` is the sibling
            // counter for verification failures.
            let verifying = VerifyingReader::new(
                file,
                expected_hash,
                Some(Box::new(move || emit_integrity_failure(backend))),
            );
            Ok(Box::new(verifying) as Box<dyn AsyncRead + Send + Unpin>)
        })
    }

    /// Range-honouring read.
    ///
    /// Stats the file to resolve `From` / `Suffix` to absolute
    /// offsets, then `seek`s — never `read+drop` — so a 1 GB blob
    /// served as `bytes=$LAST-` does not buffer the preceding bytes.
    /// The returned `AsyncRead` is `take(len)`-bounded so the wire
    /// stream is exactly the resolved-range size.
    ///
    /// Suffix clamping: `Suffix { last }` with `last >= size` collapses
    /// to the whole content per RFC 7233 §2.1.
    ///
    /// Note: range reads SKIP the `VerifyingReader` integrity check
    /// applied in `get`. The verifier hashes from offset 0 and only
    /// validates at EOF — running it over a slice would compare a
    /// partial digest against the full-content hash and always fail.
    /// Range reads therefore trust the underlying file bytes the same
    /// way they trust the upstream. Full-blob integrity stays the
    /// responsibility of the non-range path that clients hit on the
    /// first GET.
    fn get_range(
        &self,
        hash: &ContentHash,
        range: ByteRange,
    ) -> BoxFuture<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>> {
        let backend = self.backend;
        let path = self.resolve(hash);
        let hash_display = hash.to_string();
        Box::pin(async move {
            let mut guard = MetricGuard::new(backend, values::OPERATION_GET);
            // Stat first — needed to resolve `From` / `Suffix` against
            // the actual size and to surface NotFound for an absent
            // hash with the same shape `get` returns.
            let size = match fs::metadata(&path).await {
                Ok(m) => m.len(),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    debug!(hash = %hash_display, "get_range: not found");
                    guard.finish_not_found();
                    return Err(DomainError::NotFound {
                        entity: "content",
                        id: hash_display,
                    });
                }
                Err(e) => {
                    warn!(hash = %hash_display, error = %e, "get_range stat failed");
                    return Err(DomainError::Invariant(format!("storage stat failed: {e}")));
                }
            };

            let (offset, len) = match range {
                ByteRange::Inclusive { start, end } => (start, end - start + 1),
                ByteRange::From { start } => (start, size - start),
                ByteRange::Suffix { last } => {
                    // RFC 7233 §2.1: clamp `last > size` to whole content.
                    if last >= size {
                        (0, size)
                    } else {
                        (size - last, last)
                    }
                }
            };

            let mut file = fs::File::open(&path).await.map_err(|e| {
                warn!(hash = %hash_display, error = %e, "get_range failed to open file");
                DomainError::Invariant(format!("storage read failed: {e}"))
            })?;

            if offset > 0 {
                use tokio::io::AsyncSeekExt;
                file.seek(std::io::SeekFrom::Start(offset))
                    .await
                    .map_err(|e| {
                        warn!(hash = %hash_display, offset, error = %e, "seek failed");
                        DomainError::Invariant(format!("storage seek failed: {e}"))
                    })?;
            }

            debug!(hash = %hash_display, offset, len, "range retrieved");
            guard.finish_success();
            // `Take` caps the wire stream at `len`. No verifier wrap
            // here — see method docstring for the integrity rationale.
            Ok(Box::new(file.take(len)) as Box<dyn AsyncRead + Send + Unpin>)
        })
    }

    fn exists(&self, hash: &ContentHash) -> BoxFuture<'_, DomainResult<bool>> {
        let backend = self.backend;
        let path = self.resolve(hash);
        let hash_display = hash.to_string();
        Box::pin(async move {
            let mut guard = MetricGuard::new(backend, values::OPERATION_EXISTS);
            let exists = fs::try_exists(&path).await.map_err(|e| {
                warn!(hash = %hash_display, error = %e, "exists check failed");
                DomainError::Invariant(format!("storage exists check failed: {e}"))
            })?;
            debug!(hash = %hash_display, exists, "exists check");
            guard.finish_success();
            Ok(exists)
        })
    }

    fn size_of(&self, hash: &ContentHash) -> BoxFuture<'_, DomainResult<u64>> {
        let backend = self.backend;
        let path = self.resolve(hash);
        let hash_display = hash.to_string();
        Box::pin(async move {
            let mut guard = MetricGuard::new(backend, values::OPERATION_EXISTS);
            match fs::metadata(&path).await {
                Ok(meta) => {
                    let size = meta.len();
                    debug!(hash = %hash_display, size, "size_of");
                    guard.finish_success();
                    Ok(size)
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    debug!(hash = %hash_display, "size_of: not found");
                    guard.finish_not_found();
                    Err(DomainError::NotFound {
                        entity: "content",
                        id: hash_display,
                    })
                }
                Err(e) => {
                    warn!(hash = %hash_display, error = %e, "size_of stat failed");
                    Err(DomainError::Invariant(format!(
                        "storage size_of failed: {e}"
                    )))
                }
            }
        })
    }

    /// Remove the CAS object at `hash` if it exists.
    ///
    /// Called from the ingest declared-hash mismatch rollback path.
    /// Missing blobs yield `DomainError::NotFound { entity: "content", id }`
    /// — the use case treats this as a benign no-op (the rollback succeeded,
    /// whoever else removed the blob did us a favour).
    fn delete(&self, hash: &ContentHash) -> BoxFuture<'_, DomainResult<()>> {
        let backend = self.backend;
        let path = self.resolve(hash);
        let hash_display = hash.to_string();
        Box::pin(async move {
            let mut guard = MetricGuard::new(backend, values::OPERATION_DELETE);
            // Stat the object size BEFORE the delete so a successful
            // removal can attribute the exact bytes reclaimed to
            // `hort_storage_blobs_deleted_bytes_total` (ADR 0020).
            // A stat failure here is non-fatal — the delete still
            // proceeds; we simply cannot attribute its byte count
            // (size `None` ⇒ no increment, never a fabricated value).
            let size_before: Option<u64> = match fs::metadata(&path).await {
                Ok(meta) => Some(meta.len()),
                Err(_) => None,
            };
            match fs::remove_file(&path).await {
                Ok(()) => {
                    debug!(hash = %hash_display, "deleted");
                    guard.finish_success();
                    if let Some(bytes) = size_before {
                        crate::metrics::emit_blob_deleted_bytes(backend, bytes);
                    }
                    Ok(())
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    debug!(hash = %hash_display, "delete: not found");
                    guard.finish_not_found();
                    Err(DomainError::NotFound {
                        entity: "content",
                        id: hash_display,
                    })
                }
                Err(e) => {
                    warn!(hash = %hash_display, error = %e, "delete failed");
                    Err(DomainError::Invariant(format!(
                        "storage delete failed: {e}"
                    )))
                }
            }
        })
    }

    /// Walk the sharded CAS tree under `<root>/cas/` and yield every
    /// file's content hash. Used by the `CasScrubUseCase` — not on any
    /// request-serving path.
    ///
    /// Streams entries lazily via [`futures::stream::unfold`]. One shard
    /// at a time is held in memory; consumers can interleave their re-hash
    /// work between `next()` calls without forcing the walker to buffer
    /// the entire CAS up front. On a populated CAS with millions of blobs,
    /// peak memory for the walk is the depth of the open directory handles
    /// (three) plus the chunk size of one `next_entry()` future, not
    /// `O(N)` in the blob count.
    fn list_all(&self) -> BoxFuture<'_, DomainResult<BoxStream<'_, StreamItem>>> {
        let cas_root = self.root.join("cas");
        Box::pin(async move {
            let s = walk_cas_tree(&cas_root).await;
            Ok(s)
        })
    }

    fn backend_label(&self) -> &'static str {
        // Coarse label for the scrub metric — see `StoragePort::backend_label`.
        "filesystem"
    }
}

/// Walk `<root>/cas/<aa>/<bb>/` and return a `BoxStream` yielding one
/// `StreamItem` per file.
///
/// - Missing `cas/` root → yield an empty stream (the scrubber's valid
///   result for a fresh deployment that has not ingested anything).
/// - Unreadable shard directory → one `ReadError` for the shard, no
///   `ReadError` per missing file under it.
/// - Filenames that don't parse as a `ContentHash` → one `ReadError`
///   with the offending filename as the `key`.
/// - Per-step transient I/O error (`Interrupted`, `WouldBlock`) → the
///   walker retries the `next_entry()` once before giving up. If the
///   second attempt also fails — or fails with a non-transient kind —
///   the shard is abandoned with a `ShardTruncated` marker (the
///   `CasScrubUseCase` rolls these into `ScrubReport::shards_truncated`).
///
/// Streams via `futures::stream::unfold` so peak memory is bounded by
/// the depth of the open directory handles (≤3) plus one in-flight
/// `next_entry()` future, not by the blob count.
async fn walk_cas_tree(cas_root: &Path) -> BoxStream<'static, StreamItem> {
    // Missing `cas/` is not an error — fresh deployments haven't
    // created the tree yet; scrub reports an empty stream.
    match fs::try_exists(cas_root).await {
        Ok(false) => return Box::pin(stream::empty()),
        Ok(true) => (),
        Err(e) => {
            // We can't continue without the root; surface as a
            // single ReadError so the consumer's metric still fires
            // and the run is recorded as partial.
            let item = StreamItem::ReadError {
                key: cas_root.display().to_string(),
                err: DomainError::Invariant(format!("stat {}: {e}", cas_root.display())),
            };
            return Box::pin(stream::iter(std::iter::once(item)));
        }
    }

    let outer = match fs::read_dir(cas_root).await {
        Ok(d) => d,
        Err(e) => {
            let item = StreamItem::ReadError {
                key: cas_root.display().to_string(),
                err: DomainError::Invariant(format!("read_dir {}: {e}", cas_root.display())),
            };
            return Box::pin(stream::iter(std::iter::once(item)));
        }
    };

    let state = WalkState::new(cas_root.to_path_buf(), outer);
    let s = stream::unfold(state, walk_step);
    Box::pin(s)
}

/// State machine driving the lazy CAS-tree walk.
///
/// Owns the three nesting `ReadDir` handles (`outer` / `mid` / `inner`)
/// without borrowing into the surrounding adapter — the resulting
/// `BoxStream<'static, _>` coerces to the trait's `BoxStream<'_, _>`
/// return type with no lifetime gymnastics.
struct WalkState {
    cas_root: PathBuf,
    outer: fs::ReadDir,
    mid: Option<MidLevel>,
}

struct MidLevel {
    shard_a: PathBuf,
    mid: fs::ReadDir,
    inner: Option<InnerLevel>,
}

struct InnerLevel {
    shard_b: PathBuf,
    inner: fs::ReadDir,
}

impl WalkState {
    fn new(cas_root: PathBuf, outer: fs::ReadDir) -> Self {
        Self {
            cas_root,
            outer,
            mid: None,
        }
    }
}

/// One `unfold` step: descend deepest-first, yielding zero or one
/// `StreamItem` per call. Returns `None` when the entire tree has been
/// drained.
async fn walk_step(mut state: WalkState) -> Option<(StreamItem, WalkState)> {
    loop {
        // ---- Inner level: yield files under cas/aa/bb/ ----
        if let Some(mid) = state.mid.as_mut() {
            if let Some(inner) = mid.inner.as_mut() {
                let parent = inner.shard_b.clone();
                match step_with_retry_readdir(&mut inner.inner).await {
                    Ok(Some(file_path)) => match classify_cas_entry(&file_path).await {
                        Some(item) => return Some((item, state)),
                        None => continue,
                    },
                    Ok(None) => {
                        mid.inner = None;
                        continue;
                    }
                    Err(e) => {
                        mid.inner = None;
                        return Some((shard_truncated_item(&parent, &e), state));
                    }
                }
            }

            // ---- Mid level: open inner readers under cas/aa/ ----
            let parent = mid.shard_a.clone();
            match step_with_retry_readdir(&mut mid.mid).await {
                Ok(Some(shard_b)) => {
                    if !is_dir(&shard_b).await {
                        continue;
                    }
                    match fs::read_dir(&shard_b).await {
                        Ok(inner_rd) => {
                            mid.inner = Some(InnerLevel {
                                shard_b,
                                inner: inner_rd,
                            });
                            continue;
                        }
                        Err(e) => {
                            return Some((
                                StreamItem::ReadError {
                                    key: shard_b.display().to_string(),
                                    err: DomainError::Invariant(format!("read_dir shard: {e}")),
                                },
                                state,
                            ));
                        }
                    }
                }
                Ok(None) => {
                    state.mid = None;
                    continue;
                }
                Err(e) => {
                    state.mid = None;
                    return Some((shard_truncated_item(&parent, &e), state));
                }
            }
        }

        // ---- Outer level: open mid readers under cas/ ----
        let parent = state.cas_root.clone();
        match step_with_retry_readdir(&mut state.outer).await {
            Ok(Some(shard_a)) => {
                if !is_dir(&shard_a).await {
                    continue;
                }
                match fs::read_dir(&shard_a).await {
                    Ok(mid_rd) => {
                        state.mid = Some(MidLevel {
                            shard_a,
                            mid: mid_rd,
                            inner: None,
                        });
                        continue;
                    }
                    Err(e) => {
                        return Some((
                            StreamItem::ReadError {
                                key: shard_a.display().to_string(),
                                err: DomainError::Invariant(format!("read_dir shard: {e}")),
                            },
                            state,
                        ));
                    }
                }
            }
            Ok(None) => return None,
            Err(e) => {
                return Some((shard_truncated_item(&parent, &e), state));
            }
        }
    }
}

/// Convenience: step one entry off a `tokio::fs::ReadDir` with the
/// retry policy applied. The free `step_dir_with_retry` lives at
/// module scope so its retry semantics can be exercised by unit
/// tests without spinning up a real filesystem; this wrapper inlines
/// the same one-shot retry against `tokio::fs::ReadDir` because a
/// closure capturing `&mut ReadDir` can't outlive its async block.
async fn step_with_retry_readdir(rd: &mut fs::ReadDir) -> std::io::Result<Option<PathBuf>> {
    let first = rd
        .next_entry()
        .await
        .map(|opt| opt.map(|entry| entry.path()));
    match first {
        Ok(opt) => Ok(opt),
        Err(e) if is_transient_io_error(&e) => rd
            .next_entry()
            .await
            .map(|opt| opt.map(|entry| entry.path())),
        Err(e) => Err(e),
    }
}

/// Return `true` for an `io::ErrorKind` we are willing to retry once.
/// `Interrupted` (EINTR) is the canonical case — a signal raced our
/// syscall. `WouldBlock` covers the rare configuration where the dir
/// handle is non-blocking and the kernel queue is momentarily empty;
/// retry catches the spurious wake-up. Other kinds (`PermissionDenied`,
/// `Other`, etc.) are terminal — retrying a hard error just busy-loops.
fn is_transient_io_error(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
    )
}

/// Run an async `read_dir` step under the retry policy: at most one
/// retry on a transient `io::Error`, returning the second result
/// directly (whether ok, error, or eof).
///
/// Test-only seam for the per-step retry policy. The production walker
/// inlines the same retry shape inside [`step_with_retry_readdir`]
/// because a closure capturing `&mut tokio::fs::ReadDir` cannot
/// outlive its async body. Both sites delegate to
/// [`is_transient_io_error`] to keep the policy single-sourced; this
/// helper exists so unit tests can drive the policy with synthetic
/// closures without spinning up a real filesystem.
#[cfg(test)]
async fn step_dir_with_retry<F, Fut>(mut step: F) -> std::io::Result<Option<PathBuf>>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::io::Result<Option<PathBuf>>>,
{
    match step().await {
        Ok(opt) => Ok(opt),
        Err(e) if is_transient_io_error(&e) => {
            // Single retry — second result is final, regardless of
            // ok/err. Two transient errors in a row is treated as a
            // persistent fault and the caller abandons the shard.
            step().await
        }
        Err(e) => Err(e),
    }
}

/// Build a `StreamItem::ShardTruncated` marker for a directory the
/// walker abandoned mid-iteration. The consumer
/// (`CasScrubUseCase`) increments `ScrubReport::shards_truncated`
/// for each one.
fn shard_truncated_item(parent: &Path, e: &std::io::Error) -> StreamItem {
    warn!(
        parent = %parent.display(),
        error = %e,
        "cas walk abandoning shard after transient-error retry"
    );
    StreamItem::ShardTruncated {
        key: parent.display().to_string(),
        err: DomainError::Invariant(format!("read_dir entry: {e}")),
    }
}

/// Classify a leaf entry under the shard tree.
///
/// - Regular file whose filename is a valid `ContentHash` → `Hash`
/// - Regular file whose filename is not a valid `ContentHash` →
///   `ReadError` with the offending path as `key`
/// - Anything else (symlink, sub-dir, device file) → `None` (skip)
async fn classify_cas_entry(path: &Path) -> Option<StreamItem> {
    let meta = match fs::metadata(path).await {
        Ok(m) => m,
        Err(e) => {
            return Some(StreamItem::ReadError {
                key: path.display().to_string(),
                err: DomainError::Invariant(format!("metadata: {e}")),
            });
        }
    };
    if !meta.is_file() {
        return None;
    }
    let name = path.file_name().and_then(|os| os.to_str()).unwrap_or("");
    match name.parse::<ContentHash>() {
        Ok(h) => Some(StreamItem::Hash(h)),
        Err(_) => Some(StreamItem::ReadError {
            key: path.display().to_string(),
            err: DomainError::Validation(format!("filename is not a SHA-256 hex: {name}")),
        }),
    }
}

async fn is_dir(path: &Path) -> bool {
    matches!(fs::metadata(path).await.map(|m| m.is_dir()), Ok(true))
}

/// Create a directory and all parents, mapping I/O errors to `DomainError`.
///
/// On Unix, every level under `stop_at` is chmod'd to 0o700 once
/// `create_dir_all` returns (ADR 0026 + `docs/architecture/security.md`).
/// The walk stops at — and does NOT modify — `stop_at` itself: that is the
/// operator-controlled CAS root, which `prepare_root` only inspects (and
/// warns about) but never mutates. If `path` is not strictly inside
/// `stop_at`, the chmod is skipped — defensive against an unexpected
/// callsite.
///
/// `std::fs::create_dir_all` does NOT accept a mode argument; the
/// chmod must be a separate syscall. There is a small race window
/// between the mkdir and the chmod where the directory exists at the
/// process umask default; we accept this because the file written
/// into the leaf directory is itself 0o600 via `OpenOptions::mode`.
async fn ensure_dir(path: &Path, stop_at: &Path) -> DomainResult<()> {
    fs::create_dir_all(path).await.map_err(|e| {
        warn!(path = %path.display(), error = %e, "failed to create directory");
        DomainError::Invariant(format!("storage mkdir failed: {e}"))
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        // Walk from `path` up to (but not including) `stop_at`, chmod'ing
        // each level. We must chmod every level — `create_dir_all` may
        // have created any subset of intermediates and we don't track
        // which were new, so an unconditional chmod-to-0o700 is the
        // safe pattern. Idempotent on already-tight directories.
        let mut current = path;
        loop {
            if current == stop_at {
                break;
            }
            // Defensive: if `current` is not inside `stop_at`, abort the
            // walk rather than chmod paths outside the storage root.
            if !current.starts_with(stop_at) {
                break;
            }
            if let Err(e) =
                fs::set_permissions(current, std::fs::Permissions::from_mode(0o700)).await
            {
                // Non-fatal: the file written into this directory is
                // itself 0o600, so a laxer dir mode does not leak the
                // bytes — only the existence of the hash. Surface the
                // failure at warn! so audits see it without bringing
                // ingest down.
                warn!(
                    path = %current.display(),
                    error = %e,
                    "failed to chmod 0o700 on storage directory; \
                     directory listing may remain readable to others"
                );
            }
            match current.parent() {
                Some(parent) => current = parent,
                None => break,
            }
        }
    }
    // Reference `stop_at` on non-unix to keep the parameter live.
    #[cfg(not(unix))]
    {
        let _ = stop_at;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt;

    use super::*;

    /// Helper: create a `FilesystemStorage` backed by a temp directory.
    fn storage(dir: &tempfile::TempDir) -> FilesystemStorage {
        FilesystemStorage::new(dir.path().to_path_buf())
    }

    /// Helper: put bytes into storage and return the result.
    async fn put_bytes(s: &FilesystemStorage, data: &[u8]) -> PutResult {
        let cursor = Box::new(std::io::Cursor::new(data.to_vec()));
        s.put(cursor).await.unwrap()
    }

    /// Helper: get bytes from storage by hash.
    async fn get_bytes(s: &FilesystemStorage, hash: &ContentHash) -> Vec<u8> {
        let mut reader = s.get(hash).await.unwrap();
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        buf
    }

    /// SHA-256 of b"hello world" (precomputed).
    const HELLO_WORLD_SHA256: &str =
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    #[tokio::test]
    async fn put_returns_correct_hash_for_known_content() {
        let dir = tempfile::tempdir().unwrap();
        let s = storage(&dir);
        let result = put_bytes(&s, b"hello world").await;
        assert_eq!(result.hash.as_ref(), HELLO_WORLD_SHA256);
        assert_eq!(result.size_bytes, 11);
    }

    #[tokio::test]
    async fn put_then_get_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let s = storage(&dir);
        let data = b"round-trip test payload with some variety \x00\xff";
        let result = put_bytes(&s, data).await;
        assert_eq!(result.size_bytes, data.len() as u64);
        let retrieved = get_bytes(&s, &result.hash).await;
        assert_eq!(retrieved, data);
    }

    #[tokio::test]
    async fn put_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let s = storage(&dir);
        let r1 = put_bytes(&s, b"hello world").await;
        let r2 = put_bytes(&s, b"hello world").await;
        // Hash and size match across the two calls; `created` distinguishes
        // the fresh write (first) from the dedup (second).
        assert_eq!(r1.hash, r2.hash);
        assert_eq!(r1.size_bytes, r2.size_bytes);
        assert!(r1.created, "first put must be a fresh write");
        assert!(!r2.created, "second put must be a dedup");
        // Content is still retrievable.
        let retrieved = get_bytes(&s, &r1.hash).await;
        assert_eq!(retrieved, b"hello world");
    }

    #[tokio::test]
    async fn get_missing_hash_returns_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let s = storage(&dir);
        let hash: ContentHash = HELLO_WORLD_SHA256.parse().unwrap();
        match s.get(&hash).await {
            Err(DomainError::NotFound {
                entity: "content", ..
            }) => {} // expected
            Err(other) => panic!("expected NotFound, got: {other:?}"),
            Ok(_) => panic!("expected NotFound, got Ok"),
        }
    }

    #[tokio::test]
    async fn exists_true_after_put_false_before() {
        let dir = tempfile::tempdir().unwrap();
        let s = storage(&dir);
        let hash: ContentHash = HELLO_WORLD_SHA256.parse().unwrap();

        assert!(!s.exists(&hash).await.unwrap());

        put_bytes(&s, b"hello world").await;

        assert!(s.exists(&hash).await.unwrap());
    }

    /// `size_of` returns the stored byte count after `put`, and
    /// `NotFound` when the hash is absent.
    #[tokio::test]
    async fn size_of_after_put_reports_correct_length() {
        let dir = tempfile::tempdir().unwrap();
        let s = storage(&dir);
        let payload: &[u8] = b"hello world";
        let put = put_bytes(&s, payload).await;

        let size = s.size_of(&put.hash).await.unwrap();
        assert_eq!(size, payload.len() as u64);
    }

    #[tokio::test]
    async fn size_of_missing_hash_returns_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let s = storage(&dir);
        let hash: ContentHash = HELLO_WORLD_SHA256.parse().unwrap();
        match s.size_of(&hash).await {
            Err(DomainError::NotFound {
                entity: "content", ..
            }) => {}
            Err(other) => panic!("expected NotFound, got: {other:?}"),
            Ok(_) => panic!("expected NotFound, got Ok"),
        }
    }

    /// A blob whose bytes have been modified on disk after `put` must surface
    /// as `io::ErrorKind::InvalidData` when the returned stream is read to
    /// EOF (ADR 0003). Guards against silent corruption serving via the
    /// adapter's `get` path.
    #[tokio::test]
    async fn get_stream_errors_when_blob_is_tampered_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let s = storage(&dir);
        let r = put_bytes(&s, b"hello world").await;

        // Tamper: overwrite the stored file with different bytes. The
        // resolved path reuses the adapter's own derivation — an operator
        // (or attacker with filesystem write access) bypassing the port
        // cannot produce different bytes at the same key through the
        // normal path, but can via direct fs writes.
        let stored_path = s.resolve(&r.hash);
        fs::write(&stored_path, b"TAMPERED").await.unwrap();

        // Reading the stream to end must fail — integrity check fires
        // at EOF. The error kind is `InvalidData`; the message names
        // both the expected and the computed hash for ops.
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
        let dir = tempfile::tempdir().unwrap();
        let s = storage(&dir);
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

    /// Capture metrics emitted by the async block by installing a local
    /// recorder for the duration of the closure. A nested runtime drives
    /// the async code because `metrics::with_local_recorder` takes a sync
    /// closure.
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
    fn fs_put_success_emits_counter_and_histogram() {
        let snap = capture_async(|| async {
            let dir = tempfile::tempdir().unwrap();
            let s = storage(&dir);
            put_bytes(&s, b"hello world").await;
        });
        let entries = snap.into_vec();
        assert_counter(
            &entries,
            "hort_storage_operations_total",
            &[
                (labels::BACKEND, values::BACKEND_FILESYSTEM),
                (labels::OPERATION, values::OPERATION_PUT),
                (labels::RESULT, "success"),
            ],
            1,
        );
        assert_histogram_has_sample(
            &entries,
            "hort_storage_operation_duration_seconds",
            &[
                (labels::BACKEND, values::BACKEND_FILESYSTEM),
                (labels::OPERATION, values::OPERATION_PUT),
            ],
        );
    }

    #[test]
    fn fs_put_dedup_emits_dedup_counter_and_success_counter() {
        let snap = capture_async(|| async {
            let dir = tempfile::tempdir().unwrap();
            let s = storage(&dir);
            put_bytes(&s, b"hello world").await; // first call: new content
            put_bytes(&s, b"hello world").await; // second call: dedup
        });
        let entries = snap.into_vec();
        // Both calls count as success (the port contract is idempotent).
        assert_counter(
            &entries,
            "hort_storage_operations_total",
            &[
                (labels::BACKEND, values::BACKEND_FILESYSTEM),
                (labels::OPERATION, values::OPERATION_PUT),
                (labels::RESULT, "success"),
            ],
            2,
        );
        // But only the second was a dedup.
        assert_counter(
            &entries,
            "hort_storage_dedup_total",
            &[(labels::BACKEND, values::BACKEND_FILESYSTEM)],
            1,
        );
    }

    #[test]
    fn fs_get_success_emits_counter_and_histogram() {
        let snap = capture_async(|| async {
            let dir = tempfile::tempdir().unwrap();
            let s = storage(&dir);
            let r = put_bytes(&s, b"hello world").await;
            let _ = get_bytes(&s, &r.hash).await;
        });
        let entries = snap.into_vec();
        assert_counter(
            &entries,
            "hort_storage_operations_total",
            &[
                (labels::BACKEND, values::BACKEND_FILESYSTEM),
                (labels::OPERATION, values::OPERATION_GET),
                (labels::RESULT, "success"),
            ],
            1,
        );
        assert_histogram_has_sample(
            &entries,
            "hort_storage_operation_duration_seconds",
            &[
                (labels::BACKEND, values::BACKEND_FILESYSTEM),
                (labels::OPERATION, values::OPERATION_GET),
            ],
        );
    }

    #[test]
    fn fs_get_missing_hash_emits_not_found_result() {
        let snap = capture_async(|| async {
            let dir = tempfile::tempdir().unwrap();
            let s = storage(&dir);
            let hash: ContentHash = HELLO_WORLD_SHA256.parse().unwrap();
            let _ = s.get(&hash).await;
        });
        let entries = snap.into_vec();
        assert_counter(
            &entries,
            "hort_storage_operations_total",
            &[
                (labels::BACKEND, values::BACKEND_FILESYSTEM),
                (labels::OPERATION, values::OPERATION_GET),
                (labels::RESULT, "not_found"),
            ],
            1,
        );
    }

    /// A tampered blob discovered at read time must emit
    /// `hort_storage_integrity_failures_total{backend}` exactly once
    /// (ADR 0003). The `hort_storage_operations_total` for the get call
    /// still records `result=success` — the lookup succeeded; the
    /// verification failure is a separate, sibling event.
    #[test]
    fn fs_get_tampered_blob_emits_integrity_failure_counter() {
        let snap = capture_async(|| async {
            let dir = tempfile::tempdir().unwrap();
            let s = storage(&dir);
            let r = put_bytes(&s, b"hello world").await;
            // Tamper the stored bytes to trigger a verification failure.
            let stored_path = s.resolve(&r.hash);
            fs::write(&stored_path, b"TAMPERED").await.unwrap();
            let mut reader = s.get(&r.hash).await.unwrap();
            let mut out = Vec::new();
            let _ = reader.read_to_end(&mut out).await;
        });
        let entries = snap.into_vec();
        assert_counter(
            &entries,
            "hort_storage_integrity_failures_total",
            &[(labels::BACKEND, values::BACKEND_FILESYSTEM)],
            1,
        );
    }

    // ----------------------------------------------------------------------
    // Temp-file hygiene tests
    // ----------------------------------------------------------------------

    /// Construction creates `<root>/.staging/` with mode `0o700` on Unix.
    #[cfg(unix)]
    #[tokio::test]
    async fn new_creates_staging_dir_with_mode_0o700() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let _s = FilesystemStorage::new(dir.path().to_path_buf());

        let staging = dir.path().join(".staging");
        assert!(staging.exists(), ".staging dir must exist after new()");
        assert!(staging.is_dir(), ".staging must be a directory");

        let meta = std::fs::metadata(&staging).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            ".staging dir must be mode 0o700 (owner rwx only), got {mode:o}"
        );
    }

    /// Construction is idempotent when `.staging/` already exists at 0o700.
    #[cfg(unix)]
    #[tokio::test]
    async fn new_is_idempotent_with_existing_staging_at_0o700() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let staging = dir.path().join(".staging");
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o700)).unwrap();

        // Second call must not panic / error; still 0o700.
        let _s = FilesystemStorage::new(dir.path().to_path_buf());

        let meta = std::fs::metadata(&staging).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "existing 0o700 staging must remain 0o700");
    }

    /// Construction against an existing `.staging/` at 0o755 re-chmods to 0o700.
    ///
    /// We tighten the mode defensively — leaving it world-readable would
    /// defeat the whole point of the staging subdir. The spec allows either
    /// "chmod back" or "accept any existing mode"; we pick chmod for
    /// belt-and-braces. See the report accompanying this change.
    #[cfg(unix)]
    #[tokio::test]
    async fn new_rechmods_existing_staging_from_0o755_to_0o700() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let staging = dir.path().join(".staging");
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o755)).unwrap();

        let _s = FilesystemStorage::new(dir.path().to_path_buf());

        let meta = std::fs::metadata(&staging).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "existing world-readable staging must be re-chmod'd to 0o700, got {mode:o}"
        );
    }

    /// `detect_world_readable_bits(mode)` returns `Some(mode)` when any of the
    /// world (`o`) bits are set, `None` otherwise.
    ///
    /// This is the structural assertion that proves the `warn!` would fire
    /// in `new()` against a world-readable root. Capturing `tracing` events
    /// requires a subscriber dep (`tracing_test`) that the workspace does
    /// not currently carry; splitting the detection into a pure helper is
    /// simpler and covers the same branch.
    #[cfg(unix)]
    #[test]
    fn detect_world_readable_bits_flags_any_world_bit() {
        assert_eq!(detect_world_readable_bits(0o700), None);
        assert_eq!(detect_world_readable_bits(0o750), None);
        assert_eq!(detect_world_readable_bits(0o770), None);
        // Any world bit → Some(mode).
        assert_eq!(detect_world_readable_bits(0o701), Some(0o701)); // world-exec
        assert_eq!(detect_world_readable_bits(0o702), Some(0o702)); // world-write
        assert_eq!(detect_world_readable_bits(0o704), Some(0o704)); // world-read
        assert_eq!(detect_world_readable_bits(0o755), Some(0o755));
        assert_eq!(detect_world_readable_bits(0o777), Some(0o777));
    }

    /// Constructing against a world-readable root does NOT fail startup
    /// (spec says warn, not fail). The warn itself is covered structurally
    /// by `detect_world_readable_bits_flags_any_world_bit`.
    #[cfg(unix)]
    #[tokio::test]
    async fn new_does_not_fail_on_world_readable_root() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();

        let _s = FilesystemStorage::new(dir.path().to_path_buf());
        // If we got here, construction didn't panic. Test passes.

        // Restore 0o700 so tempfile can clean up on drop without trouble.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    /// `put()` stages its temp file under `<root>/.staging/.tmp.<uuid>`, not
    /// under `<root>/` directly. After a successful put the staging dir is
    /// empty and the final content-hashed file exists at the CAS key.
    #[cfg(unix)]
    #[tokio::test]
    async fn put_stages_temp_file_under_staging_dir() {
        let dir = tempfile::tempdir().unwrap();
        let s = storage(&dir);

        let result = put_bytes(&s, b"hello world").await;

        // Staging dir is empty after put completes (rename consumed the tmp).
        let staging = dir.path().join(".staging");
        let leftovers: Vec<_> = std::fs::read_dir(&staging)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().into_string().unwrap())
            .collect();
        assert!(
            leftovers.is_empty(),
            ".staging/ must be empty after successful put, got: {leftovers:?}"
        );

        // Final content-hashed file lives at the CAS key under root.
        let final_path = s.resolve(&result.hash);
        assert!(
            final_path.exists(),
            "final CAS file must exist at {}",
            final_path.display()
        );
        assert!(
            final_path.starts_with(dir.path()),
            "final CAS path must be inside root"
        );

        // No stray `.tmp.*` directly under root (pre-Item-11 behaviour).
        let root_entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().into_string().unwrap())
            .collect();
        for name in &root_entries {
            assert!(
                !name.starts_with(".tmp."),
                "temp files must NOT be staged under root directly; found {name} in {root_entries:?}"
            );
        }
    }

    // ----------------------------------------------------------------------
    // File / directory mode pinning
    //
    // Audit invariant (BSI ORP.4, GDPR Art 32): CAS blobs land at 0o600
    // and CAS directories (staging + shard) at 0o700. The modes are NOT
    // configurable — operators cannot widen them. A regression that
    // reverts to the umask-default 0o644 / 0o755 on a multi-tenant host
    // would expose ingested artifacts to local readers.
    // (ADR 0026 + `docs/architecture/security.md`)
    // ----------------------------------------------------------------------

    /// `put` writes the final blob with mode 0o600 (owner rw, no group,
    /// no world). Verifies that `OpenOptions::mode` set on the staging
    /// temp file survives `fs::rename` to the final CAS path —
    /// Unix-rename preserves the inode + its mode bits.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_cas_blob_mode_is_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let s = storage(&dir);

        let result = put_bytes(&s, b"hello world").await;
        let final_path = s.resolve(&result.hash);

        let meta = std::fs::metadata(&final_path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode,
            0o600,
            "CAS blob must be mode 0o600 (owner rw only) — got {mode:o} at {}",
            final_path.display()
        );
    }

    /// CAS shard directories (`<root>/cas/<aa>/<bb>/`) created by
    /// `ensure_dir` during `put` land at mode 0o700.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_cas_shard_dirs_mode_is_0700() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let s = storage(&dir);

        let result = put_bytes(&s, b"hello world").await;
        let final_path = s.resolve(&result.hash);

        // Walk up from the blob: bb dir, aa dir.
        let bb = final_path.parent().unwrap();
        let aa = bb.parent().unwrap();

        for d in [bb, aa] {
            let meta = std::fs::metadata(d).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(
                mode,
                0o700,
                "CAS shard dir {} must be mode 0o700 — got {mode:o}",
                d.display()
            );
        }
    }

    // ----------------------------------------------------------------------
    // list_all walk tests
    // ----------------------------------------------------------------------

    use futures::StreamExt;

    /// Drain the `list_all` stream into a `Vec<StreamItem>` for assertion.
    async fn collect_list_all(s: &FilesystemStorage) -> Vec<StreamItem> {
        let stream = s.list_all().await.unwrap();
        stream.collect().await
    }

    /// Fresh storage against an empty root yields an empty list. Covers
    /// the "no `cas/` directory yet" branch — an as-yet-unused
    /// deployment scrubs cleanly.
    #[tokio::test]
    async fn list_all_empty_root_yields_empty_stream() {
        let dir = tempfile::tempdir().unwrap();
        let s = storage(&dir);
        let items = collect_list_all(&s).await;
        assert!(items.is_empty());
    }

    /// After a single `put`, the stored hash appears in `list_all`. Pins
    /// the end-to-end wiring: `put` writes under the sharded tree, walk
    /// finds it.
    #[tokio::test]
    async fn list_all_yields_put_hash() {
        let dir = tempfile::tempdir().unwrap();
        let s = storage(&dir);
        let r = put_bytes(&s, b"hello world").await;

        let items = collect_list_all(&s).await;
        let hashes: Vec<_> = items
            .iter()
            .filter_map(|it| match it {
                StreamItem::Hash(h) => Some(h.clone()),
                // Filesystem walks may emit `ShardTruncated` when a
                // per-step retry is exhausted; this happy-path test
                // never injects such an error so neither variant
                // should be present, but the match must be exhaustive.
                StreamItem::ReadError { .. } | StreamItem::ShardTruncated { .. } => None,
            })
            .collect();
        assert_eq!(hashes, vec![r.hash]);
    }

    /// Multiple puts all show up — the walk traverses every shard.
    #[tokio::test]
    async fn list_all_yields_all_hashes_after_multiple_puts() {
        let dir = tempfile::tempdir().unwrap();
        let s = storage(&dir);
        let r1 = put_bytes(&s, b"hello world").await;
        let r2 = put_bytes(&s, b"").await;
        let r3 = put_bytes(&s, b"third payload").await;

        let items = collect_list_all(&s).await;
        let mut hashes: Vec<_> = items
            .iter()
            .filter_map(|it| match it {
                StreamItem::Hash(h) => Some(h.to_string()),
                StreamItem::ReadError { .. } | StreamItem::ShardTruncated { .. } => None,
            })
            .collect();
        hashes.sort();
        let mut expected = vec![
            r1.hash.to_string(),
            r2.hash.to_string(),
            r3.hash.to_string(),
        ];
        expected.sort();
        assert_eq!(hashes, expected);
    }

    /// A file whose name is NOT a SHA-256 hex planted under the shard
    /// tree surfaces as a `StreamItem::ReadError` (not silently
    /// ignored, not a stream abort).
    #[tokio::test]
    async fn list_all_surfaces_non_hash_filenames_as_read_error() {
        let dir = tempfile::tempdir().unwrap();
        let s = storage(&dir);
        // Plant a bogus file under cas/aa/bb/.
        let shard = dir.path().join("cas").join("aa").join("bb");
        std::fs::create_dir_all(&shard).unwrap();
        let bogus = shard.join("not-a-sha256");
        std::fs::write(&bogus, b"garbage").unwrap();

        let items = collect_list_all(&s).await;
        let read_errors: Vec<_> = items
            .iter()
            .filter(|it| matches!(it, StreamItem::ReadError { .. }))
            .collect();
        assert_eq!(
            read_errors.len(),
            1,
            "expected 1 ReadError for bogus filename, got {items:?}"
        );
    }

    /// `.staging/` entries are NOT visible to `list_all`. The staging
    /// subdir lives OUTSIDE `cas/` and must not pollute the scrub.
    #[tokio::test]
    async fn list_all_ignores_staging_dir() {
        let dir = tempfile::tempdir().unwrap();
        let s = storage(&dir);
        // Put something (creates .staging/ + cas/).
        let _ = put_bytes(&s, b"hello world").await;
        // Plant a bogus file inside .staging/ — a leaked temp from a
        // prior crashed write.
        let staging_bogus = dir.path().join(".staging").join(".tmp.leaked");
        std::fs::write(&staging_bogus, b"leaked").unwrap();

        let items = collect_list_all(&s).await;
        // The walk only descends into cas/; the leaked file does not
        // show up as a ReadError.
        let read_errors: Vec<_> = items
            .iter()
            .filter(|it| matches!(it, StreamItem::ReadError { .. }))
            .collect();
        assert!(read_errors.is_empty(), "staging leak leaked into scrub");
    }

    /// The adapter's `backend_label` is the coarse scrub-metric label.
    #[test]
    fn filesystem_backend_label_is_filesystem_coarse() {
        let dir = tempfile::tempdir().unwrap();
        let s = storage(&dir);
        assert_eq!(s.backend_label(), "filesystem");
    }

    // ----------------------------------------------------------------------
    // get_range contract suite
    // ----------------------------------------------------------------------

    /// Run the generic `StoragePort::get_range` contract suite against
    /// `FilesystemStorage`. Byte-exact checks across `Inclusive`,
    /// `From`, and `Suffix` variants live in `range_contract`; this
    /// test wires the filesystem adapter as the SUT and seeds the
    /// 1024-byte fixture content.
    #[tokio::test]
    async fn filesystem_get_range_contract() {
        let dir = tempfile::tempdir().unwrap();
        let s = Arc::new(storage(&dir));
        let content = crate::range_contract::fixture_payload();
        let put = s
            .put(Box::new(std::io::Cursor::new(content.clone())))
            .await
            .unwrap();
        crate::range_contract::run_contract(s.clone(), put.hash, &content).await;
    }

    use std::sync::Arc;

    // ----------------------------------------------------------------------
    // step_dir_with_retry tests
    // ----------------------------------------------------------------------

    /// One ok call returns the path with no retry attempted.
    #[tokio::test]
    async fn step_dir_with_retry_returns_ok_immediately_when_no_error() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = calls.clone();
        let target = PathBuf::from("/cas/aa/bb/file");
        let target2 = target.clone();
        let outcome = step_dir_with_retry(move || {
            calls2.fetch_add(1, Ordering::SeqCst);
            let t = target2.clone();
            async move { Ok::<_, std::io::Error>(Some(t)) }
        })
        .await;
        assert!(matches!(outcome, Ok(Some(p)) if p == target));
        assert_eq!(calls.load(Ordering::SeqCst), 1, "no retry on ok");
    }

    /// Interrupted on the first call → exactly one retry; second call ok.
    #[tokio::test]
    async fn step_dir_with_retry_retries_once_on_interrupted() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = calls.clone();
        let target = PathBuf::from("/cas/aa/bb/file");
        let target2 = target.clone();
        let outcome = step_dir_with_retry(move || {
            let n = calls2.fetch_add(1, Ordering::SeqCst);
            let t = target2.clone();
            async move {
                if n == 0 {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "EINTR injected",
                    ))
                } else {
                    Ok(Some(t))
                }
            }
        })
        .await;
        assert!(matches!(outcome, Ok(Some(p)) if p == target));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "exactly one retry on Interrupted"
        );
    }

    /// `WouldBlock` follows the same retry path as `Interrupted`.
    #[tokio::test]
    async fn step_dir_with_retry_retries_once_on_would_block() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = calls.clone();
        let outcome = step_dir_with_retry(move || {
            let n = calls2.fetch_add(1, Ordering::SeqCst);
            async move {
                if n == 0 {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "WouldBlock injected",
                    ))
                } else {
                    Ok::<_, std::io::Error>(None)
                }
            }
        })
        .await;
        assert!(matches!(outcome, Ok(None)));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// Two transient errors in a row → terminal: caller gets the
    /// second error and does NOT see a third call.
    #[tokio::test]
    async fn step_dir_with_retry_terminal_after_persistent_transient() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = calls.clone();
        let outcome = step_dir_with_retry(move || {
            calls2.fetch_add(1, Ordering::SeqCst);
            async move {
                Err::<Option<PathBuf>, _>(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "persistent EINTR",
                ))
            }
        })
        .await;
        assert!(outcome.is_err());
        assert_eq!(outcome.unwrap_err().kind(), std::io::ErrorKind::Interrupted);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "exactly one retry; persistent transient is terminal after second attempt"
        );
    }

    /// Non-transient error (e.g. PermissionDenied) is terminal on the
    /// first hit — no retry, retry policy is for transient kinds only.
    #[tokio::test]
    async fn step_dir_with_retry_does_not_retry_permission_denied() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = calls.clone();
        let outcome = step_dir_with_retry(move || {
            calls2.fetch_add(1, Ordering::SeqCst);
            async move {
                Err::<Option<PathBuf>, _>(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "EACCES",
                ))
            }
        })
        .await;
        assert!(outcome.is_err());
        assert_eq!(
            outcome.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "non-transient errors are terminal on first hit"
        );
    }

    // ----------------------------------------------------------------------
    // walk_cas_tree streaming-shape tests
    // ----------------------------------------------------------------------

    /// Structural assertion that `walk_cas_tree` returns a stream type,
    /// not a `Vec`. The previous implementation collected all entries
    /// into a `Vec<StreamItem>` before returning; on a populated CAS
    /// (1M entries) that materialised the entire list before the
    /// scrubber saw the first one. Type-level proof that we now hand
    /// out a `BoxStream` is the cheapest unit-test signature for the
    /// memory-shape property — actually building a 1M-entry tree in a
    /// unit test would be wall-clock prohibitive.
    #[tokio::test]
    async fn walk_cas_tree_returns_a_stream_not_a_vec() {
        use futures::StreamExt;
        let dir = tempfile::tempdir().unwrap();
        let s = storage(&dir);
        let _ = put_bytes(&s, b"hello world").await;

        let cas_root = dir.path().join("cas");
        let mut stream = walk_cas_tree(&cas_root).await;
        // We can poll one item at a time; the type satisfies `Stream`.
        let first = stream.next().await;
        assert!(first.is_some(), "stream must yield at least one item");
    }

    /// Polling `next()` repeatedly drains the stream incrementally —
    /// each call returns one item, and the stream completes with
    /// `None` at EOF. This is the behavioural side of "no upfront
    /// Vec": the scrubber can interleave work between `next` calls
    /// without holding the entire entry list in memory.
    #[tokio::test]
    async fn walk_cas_tree_yields_items_lazily_one_at_a_time() {
        use futures::StreamExt;
        let dir = tempfile::tempdir().unwrap();
        let s = storage(&dir);
        // Three independent puts — three items in the stream.
        let _ = put_bytes(&s, b"hello world").await;
        let _ = put_bytes(&s, b"").await;
        let _ = put_bytes(&s, b"third payload").await;

        let cas_root = dir.path().join("cas");
        let mut stream = walk_cas_tree(&cas_root).await;
        let mut count = 0;
        while let Some(_item) = stream.next().await {
            count += 1;
            // The point of the test: between `next()` calls the
            // stream's state is suspended. We don't assert heap-usage
            // here, but the Stream type is the structural guarantee.
            if count > 100 {
                panic!("stream did not terminate; expected 3 items");
            }
        }
        assert_eq!(count, 3);
    }

    #[test]
    fn fs_exists_success_emits_counter_and_histogram() {
        let snap = capture_async(|| async {
            let dir = tempfile::tempdir().unwrap();
            let s = storage(&dir);
            let hash: ContentHash = HELLO_WORLD_SHA256.parse().unwrap();
            let _ = s.exists(&hash).await;
        });
        let entries = snap.into_vec();
        assert_counter(
            &entries,
            "hort_storage_operations_total",
            &[
                (labels::BACKEND, values::BACKEND_FILESYSTEM),
                (labels::OPERATION, values::OPERATION_EXISTS),
                (labels::RESULT, "success"),
            ],
            1,
        );
        assert_histogram_has_sample(
            &entries,
            "hort_storage_operation_duration_seconds",
            &[
                (labels::BACKEND, values::BACKEND_FILESYSTEM),
                (labels::OPERATION, values::OPERATION_EXISTS),
            ],
        );
    }

    /// Deleting a PRESENT blob increments
    /// `hort_storage_blobs_deleted_bytes_total{backend}` by exactly the
    /// blob's byte size (stat'd before the delete; ADR 0020).
    #[test]
    fn fs_delete_present_blob_increments_deleted_bytes_by_size() {
        let payload: &[u8] = b"hello world"; // 11 bytes
        let snap = capture_async(|| async {
            let dir = tempfile::tempdir().unwrap();
            let s = storage(&dir);
            let put = put_bytes(&s, payload).await;
            s.delete(&put.hash).await.expect("delete present blob");
        });
        let entries = snap.into_vec();
        assert_counter(
            &entries,
            "hort_storage_blobs_deleted_bytes_total",
            &[(labels::BACKEND, values::BACKEND_FILESYSTEM)],
            payload.len() as u64,
        );
    }

    /// Deleting an ABSENT blob (the idempotent re-purge / §6
    /// invariant 4 path) does NOT increment the bytes counter — no
    /// double-count on retry by construction.
    #[test]
    fn fs_delete_absent_blob_does_not_increment_deleted_bytes() {
        let snap = capture_async(|| async {
            let dir = tempfile::tempdir().unwrap();
            let s = storage(&dir);
            let hash: ContentHash = HELLO_WORLD_SHA256.parse().unwrap();
            // Never put — blob is absent. delete → NotFound (allowed).
            let _ = s.delete(&hash).await;
        });
        let entries = snap.into_vec();
        let found = find_metric(
            &entries,
            MetricKind::Counter,
            "hort_storage_blobs_deleted_bytes_total",
            &[(labels::BACKEND, values::BACKEND_FILESYSTEM)],
        );
        assert!(
            found.is_none(),
            "absent-blob delete must NOT emit hort_storage_blobs_deleted_bytes_total"
        );
    }
}
