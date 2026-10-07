//! Filesystem-backed `StatefulUploadStagingPort` adapter.
//!
//! Stores in-flight upload chunks under `<root>/<session_id>.part`.
//! The `.part` suffix and the flat layout keep the staging tree
//! unambiguously separate from any CAS naming scheme — there is no
//! filename a CAS adapter can emit that collides with `<uuid>.part`.
//!
//! Design: see `docs/architecture/how-to/oci-pull-through.md` §5 for OCI
//! stateful-upload context.
//!
//! # Why a dedicated adapter (not a `FilesystemStorage` helper)
//!
//! Staging bytes are pre-finalization scratch space — they are NOT
//! content-addressable and may never land in CAS. Sharing the CAS
//! adapter's directory tree or helpers would invite one of two bugs:
//!
//! - A staging leak reappearing through `StoragePort::list_all` (the
//!   CAS scrub walk), polluting the scrub report with pre-hash bytes.
//! - A staging key colliding with a CAS key if a future refactor
//!   accidentally tried to dedup the two naming schemes.
//!
//! The adapter therefore owns its own `PathBuf` root — typically
//! distinct from the CAS root — and shares no code with
//! `FilesystemStorage`.

use std::path::{Path, PathBuf};

use tokio::fs::{self, OpenOptions};
use tokio::io::{AsyncRead, AsyncSeekExt, AsyncWriteExt};
use tracing::{debug, warn};
use uuid::Uuid;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::stateful_upload_staging::{StagingAppend, StatefulUploadStagingPort};
use hort_domain::ports::BoxFuture;

/// Copy-buffer size for streaming appends. 64 KiB matches the CAS
/// adapter's transfer chunk so the two hot paths share the same memory
/// working-set shape.
const CHUNK_SIZE: usize = 64 * 1024;

/// Suffix appended to every staging filename. The choice is deliberate:
///
/// - CAS keys are 64-char lowercase hex (SHA-256); staging keys are
///   36-char hyphenated UUIDs plus `.part`. The two namespaces are
///   disjoint by length alone — a defensive check that survives future
///   naming-scheme refactors.
/// - The `.part` suffix also makes leaked staging files immediately
///   recognisable in a directory listing without having to know the
///   sharding rules of either adapter.
const STAGING_SUFFIX: &str = ".part";

/// Filesystem adapter for [`StatefulUploadStagingPort`].
///
/// Every session is one file on disk. `append_at` seeks to the caller's
/// asserted offset and writes there — deliberately **not** `O_APPEND`,
/// whose "every write lands at whatever the current end is" semantics
/// are exactly what lets a file outgrow the progress its owner recorded.
/// `stream_read` returns a fresh `tokio::fs::File` positioned at byte 0.
/// `delete` tolerates missing files — finalize and GC may race to clean
/// up.
pub struct FilesystemStatefulUploadStaging {
    root: PathBuf,
}

impl FilesystemStatefulUploadStaging {
    /// Construct a staging adapter rooted at `root`.
    ///
    /// The directory is created eagerly (best-effort — failures are
    /// logged but don't panic; each `append_at` re-attempts `create_dir_all`
    /// before opening the file, matching the CAS adapter's posture of
    /// not coupling composition-root startup to filesystem state).
    ///
    /// The constructor uses sync `std::fs::create_dir_all` deliberately.
    /// This runs exactly once from `build_app_context` at startup — a
    /// single sub-millisecond syscall — and keeping it sync lets the
    /// constructor stay non-async so callers don't need `.await` at
    /// every instantiation site (matches `FilesystemStorage::new`). The
    /// hot path (`append_at`) uses `tokio::fs::create_dir_all` via
    /// `ensure_dir` on every call, so per-request IO stays async.
    ///
    /// Plumbing from the `HORT_STATEFUL_UPLOAD_STAGING_DIR` environment
    /// variable lives in `hort_server::config`; the constructor takes a
    /// raw path so unit tests can inject a `TempDir`.
    pub fn new(root: PathBuf) -> Self {
        if let Err(e) = std::fs::create_dir_all(&root) {
            warn!(
                root = %root.display(),
                error = %e,
                "failed to create stateful-upload staging root; append_at() will retry"
            );
        } else {
            // Pin the staging root to 0o700 (ADR 0026 +
            // `docs/architecture/security.md`). `create_dir_all` does not
            // take a mode, so the chmod must be a separate call after the
            // directory exists. Failure is logged but not fatal — chunk
            // files inside are themselves 0o600 via `OpenOptions::mode`,
            // so a laxer root mode does not leak chunk bytes; it would
            // only leak the existence of session UUIDs.
            //
            // This log is `debug!`, not `warn!`. The authoritative
            // chmod-as-fatal gate is `verify_writable_and_ownable`, which
            // runs from `hort-server::composition` AFTER `new()` and
            // re-attempts the chmod. If that gate succeeds, this `new()`
            // failure is stale by the time it's read — the "session UUIDs
            // may be enumerable" message is misleading once the dir IS
            // 0o700. Operators tracking real chmod failures see the gate's
            // fail-loud error (`staging_root_unwritable("chmod 0o700", …)`);
            // this `debug!` is only for diagnosing the transient case.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Err(e) =
                    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
                {
                    debug!(
                        root = %root.display(),
                        error = %e,
                        "transient chmod 0o700 failure on stateful-upload staging root; \
                         verify_writable_and_ownable() is the authoritative gate"
                    );
                }
            }
        }
        Self { root }
    }

    /// Fail-loud boot-time gate: the staging root must be creatable,
    /// writable, and (on Unix) owner-restrictable to 0o700.
    ///
    /// # Why this exists
    ///
    /// [`new`](Self::new) is deliberately best-effort: it `warn!`s
    /// (never panics / errors) on a non-creatable or non-ownable root,
    /// and every [`append_at`](StatefulUploadStagingPort::append_at)
    /// re-attempts `create_dir_all`. The original mode-pinning scope was
    /// limited to the narrow *writable-but-unownable* case (a laxer mode
    /// only leaks the existence of session UUIDs; chunk files are
    /// themselves 0o600). It did **not** anticipate the chart's own
    /// `readOnlyRootFilesystem: true` making the S3-default root *entirely
    /// unwritable*, where the failure is not "laxer mode" but "chunked
    /// upload non-functional, silently" — `append_at()` "retries" forever and
    /// OCI `docker push` / Git LFS 5xx at runtime with no readiness signal.
    ///
    /// This method brings that surface under the fail-closed/loud discipline
    /// (ADR 0007): the composition root calls it once at boot and turns an
    /// `Err` into a **fatal boot error** (the pod never enters the Service),
    /// exactly as `KubernetesSecretWriterImpl::try_in_cluster()` does for
    /// the fallback-PAT-rotation writer. It is an *inherent* method, **not**
    /// a [`StatefulUploadStagingPort`] trait method — the port signature is
    /// unchanged.
    ///
    /// The per-`append_at()` `warn!` stays as transient-case
    /// defense-in-depth (a root that becomes non-writable *after* a
    /// healthy boot); this gate is the boot-time fail-loud addition.
    ///
    /// # Errors
    ///
    /// `DomainError::Invariant` if the root cannot be created, a probe
    /// file cannot be created+removed under it, or (Unix) the 0o700
    /// chmod fails — every case where chunked upload would be silently
    /// dead. The message carries the io-error kind; it never carries a
    /// session id / UUID (cardinality + secondary-symptom enumeration
    /// concern — session UUIDs must not appear in error messages).
    pub async fn verify_writable_and_ownable(&self) -> DomainResult<()> {
        // (1) The directory must exist / be creatable. This is the
        // EROFS-on-read-only-rootfs case.
        fs::create_dir_all(&self.root)
            .await
            .map_err(|e| staging_root_unwritable("create_dir_all", &e))?;

        // (2) On Unix, pin 0o700 and treat a chmod failure as fatal at
        // the gate (a writable-but-unownable root leaks session-UUID
        // existence to other local users).
        // `new()`'s post-create chmod stays a warn for the transient
        // case; here it is part of the loud boot contract.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.root, std::fs::Permissions::from_mode(0o700))
                .await
                .map_err(|e| staging_root_unwritable("chmod 0o700", &e))?;
        }

        // (3) A directory can be 0o700-ownable yet still unwritable
        // (read-only mount, EROFS, full filesystem). Prove an actual
        // write succeeds by creating and removing a probe file. The
        // probe name is a fixed, non-`.part`, non-UUID sentinel so the
        // staging-orphan sweep skips it even in the (impossible-by-
        // construction) event a crash strands it; we remove it before
        // returning on the happy path so the root stays litter-free.
        let probe = self.root.join(".hort-staging-writable-probe");
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&probe)
            .await
            .map_err(|e| staging_root_unwritable("probe-file create", &e))?;
        file.write_all(b"ok")
            .await
            .map_err(|e| staging_root_unwritable("probe-file write", &e))?;
        file.flush()
            .await
            .map_err(|e| staging_root_unwritable("probe-file flush", &e))?;
        drop(file);
        fs::remove_file(&probe)
            .await
            .map_err(|e| staging_root_unwritable("probe-file cleanup", &e))?;

        Ok(())
    }

    /// Resolve a session UUID to its `.part` file path.
    fn resolve(&self, session_id: Uuid) -> PathBuf {
        // `Uuid::to_string` yields the hyphenated lowercase form,
        // which is the format OCI handlers echo in `Location:
        // /v2/.../blobs/uploads/<uuid>`. Using the same string here
        // keeps staging filenames grep-able against handler logs.
        self.root.join(format!("{session_id}{STAGING_SUFFIX}"))
    }
}

impl StatefulUploadStagingPort for FilesystemStatefulUploadStaging {
    fn append_at(
        &self,
        session_id: Uuid,
        offset: u64,
        limit: u64,
        mut stream: Box<dyn AsyncRead + Send + Unpin>,
    ) -> BoxFuture<'_, DomainResult<StagingAppend>> {
        Box::pin(async move {
            debug!(%session_id, offset, limit, op = "append_at", "stateful upload staging write");

            ensure_dir(&self.root).await?;
            let path = self.resolve(session_id);

            // Opened WITHOUT `O_APPEND`: the write position is the
            // caller's asserted `offset`, not the file's end at the
            // moment the kernel gets the write. O_APPEND would make the
            // physical length the sum of whatever arrives, which is the
            // one thing this port must not let happen — see the trait's
            // concurrency contract.
            //
            // Mode 0o600 is set atomically with O_CREAT (ADR 0026 +
            // `docs/architecture/security.md`). Because `append_at` may be
            // called many times for the same session, the mode argument
            // only takes effect on the create call (existing chunk files
            // keep their existing mode — which is also 0o600 from the
            // first write). On non-Unix the mode is silently ignored.
            let mut open_opts = OpenOptions::new();
            open_opts.create(true).write(true);
            #[cfg(unix)]
            {
                open_opts.mode(0o600);
            }
            let mut file = open_opts.open(&path).await.map_err(|e| {
                warn!(
                    %session_id,
                    op = "append_at",
                    error = %e,
                    "failed to open staging file for write"
                );
                DomainError::Invariant(format!("stateful upload staging open failed: {e}"))
            })?;

            let current = stat_len(&file, session_id).await?;
            if current < offset {
                // A gap. Writing at `offset` would leave `offset -
                // current` bytes the client never sent inside the
                // content; the finalize digest would then reject a blob
                // the registry itself corrupted. Refuse having written
                // nothing — the length is unchanged, so a retry cannot
                // grow the file either.
                warn!(
                    %session_id,
                    op = "append_at",
                    offset,
                    current,
                    "staging write offset is past the end of the staging file"
                );
                return Err(DomainError::Invariant(format!(
                    "stateful upload staging write at offset {offset} would leave a gap: \
                     staging holds {current} bytes"
                )));
            }
            if current > offset {
                // Debris: bytes beyond what the caller's record accounts
                // for, left by an earlier write whose record update never
                // landed. Dropping them is the repair — the record is the
                // authority, so these bytes can never become content, and
                // leaving them would corrupt the blob the next write
                // completes.
                debug!(
                    %session_id,
                    op = "append_at",
                    offset,
                    current,
                    "dropping unaccounted staging tail before write"
                );
                file.set_len(offset).await.map_err(|e| {
                    warn!(
                        %session_id,
                        op = "append_at",
                        error = %e,
                        "failed to truncate staging file to the caller's offset"
                    );
                    DomainError::Invariant(format!("stateful upload staging truncate failed: {e}"))
                })?;
            }
            file.seek(std::io::SeekFrom::Start(offset))
                .await
                .map_err(|e| {
                    warn!(
                        %session_id,
                        op = "append_at",
                        error = %e,
                        "failed to seek staging file to the caller's offset"
                    );
                    DomainError::Invariant(format!("stateful upload staging seek failed: {e}"))
                })?;

            // Stream copy through a fixed-size buffer so memory stays
            // bounded regardless of the body size, and never read more
            // than `limit` into the file.
            let mut buf = vec![0u8; CHUNK_SIZE];
            let mut remaining = limit;
            while remaining > 0 {
                // `remaining` is a u64 budget; the buffer slice is a
                // usize. Clamping through u64 first means the cast can
                // only ever see a value <= CHUNK_SIZE.
                let want = remaining.min(CHUNK_SIZE as u64) as usize;
                let n = read_or_invariant(&mut stream, &mut buf[..want], session_id).await?;
                if n == 0 {
                    break;
                }
                file.write_all(&buf[..n]).await.map_err(|e| {
                    warn!(
                        %session_id,
                        op = "append_at",
                        error = %e,
                        "failed to write chunk to staging file"
                    );
                    DomainError::Invariant(format!("stateful upload staging write failed: {e}"))
                })?;
                remaining -= n as u64;
            }

            // The budget ran out with the stream possibly still holding
            // bytes. Read one to find out — and discard it. The caller
            // needs the "there was more" bit to reject the request; the
            // file must not carry it, or the length exceeds the cap the
            // budget expressed.
            let truncated = if remaining == 0 {
                read_or_invariant(&mut stream, &mut buf[..1], session_id).await? > 0
            } else {
                false
            };

            // Flush pending writes so the stat below sees the bytes we
            // just wrote. `flush` is sufficient here — we don't need the
            // crash-safety of `sync_all` for scratch space (a GC sweep
            // cleans up crashed sessions anyway).
            file.flush().await.map_err(|e| {
                warn!(
                    %session_id,
                    op = "append_at",
                    error = %e,
                    "failed to flush staging file"
                );
                DomainError::Invariant(format!("stateful upload staging flush failed: {e}"))
            })?;

            // Report the file's measured length, not `offset + written`.
            // The caller cross-checks this against what it reserved, and
            // a check fed by the same arithmetic it is verifying would
            // confirm nothing.
            let total = stat_len(&file, session_id).await?;
            Ok(StagingAppend { total, truncated })
        })
    }

    fn stream_read(
        &self,
        session_id: Uuid,
    ) -> BoxFuture<'_, DomainResult<Box<dyn AsyncRead + Send + Unpin>>> {
        Box::pin(async move {
            debug!(%session_id, op = "stream_read", "stateful upload staging stream_read");
            let path = self.resolve(session_id);

            match fs::File::open(&path).await {
                Ok(file) => Ok(Box::new(file) as Box<dyn AsyncRead + Send + Unpin>),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Missing staging file on read is a client-class
                    // error (session expired, client mis-sequenced
                    // requests), not infrastructure. debug!, NotFound.
                    debug!(
                        %session_id,
                        op = "stream_read",
                        "staging file not found"
                    );
                    Err(DomainError::NotFound {
                        entity: "stateful_upload_staging",
                        id: session_id.to_string(),
                    })
                }
                Err(e) => {
                    warn!(
                        %session_id,
                        op = "stream_read",
                        error = %e,
                        "failed to open staging file for read"
                    );
                    Err(DomainError::Invariant(format!(
                        "stateful upload staging open failed: {e}"
                    )))
                }
            }
        })
    }

    fn list(&self, max: usize) -> BoxFuture<'_, DomainResult<Vec<Uuid>>> {
        Box::pin(async move {
            debug!(max, op = "list", "stateful upload staging list");

            // The staging root may not exist yet on a fresh deployment that
            // has not seen its first chunk — treat that as an empty list,
            // consistent with `delete`'s NotFound-tolerance posture. Any
            // other read_dir error is infrastructure-class and surfaces as
            // Invariant.
            let mut entries = match fs::read_dir(&self.root).await {
                Ok(rd) => rd,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(Vec::new());
                }
                Err(e) => {
                    warn!(
                        root = %self.root.display(),
                        error = %e,
                        "failed to read staging root"
                    );
                    return Err(DomainError::Invariant(format!(
                        "stateful upload staging list failed: {e}"
                    )));
                }
            };

            let mut out = Vec::with_capacity(max.min(64));
            while out.len() < max {
                let entry = match entries.next_entry().await {
                    Ok(Some(entry)) => entry,
                    Ok(None) => break,
                    Err(e) => {
                        warn!(
                            root = %self.root.display(),
                            error = %e,
                            "failed to advance staging dir iterator"
                        );
                        return Err(DomainError::Invariant(format!(
                            "stateful upload staging list iter failed: {e}"
                        )));
                    }
                };

                // Defensive: parse `<uuid>.part`. Anything that doesn't
                // strip the suffix or doesn't parse as a Uuid is litter
                // (operator-dropped files, stray subdirs) and the sweep
                // skips it silently — the next sweep retries everything.
                let name = entry.file_name();
                let Some(name_str) = name.to_str() else {
                    debug!(
                        path = %entry.path().display(),
                        "skipping non-utf8 entry in staging root"
                    );
                    continue;
                };
                let Some(stem) = name_str.strip_suffix(STAGING_SUFFIX) else {
                    debug!(
                        name = name_str,
                        "skipping non-`.part` entry in staging root"
                    );
                    continue;
                };
                match Uuid::parse_str(stem) {
                    Ok(id) => out.push(id),
                    Err(_) => {
                        debug!(name = name_str, "skipping non-uuid entry in staging root");
                    }
                }
            }

            Ok(out)
        })
    }

    fn delete(&self, session_id: Uuid) -> BoxFuture<'_, DomainResult<()>> {
        Box::pin(async move {
            debug!(%session_id, op = "delete", "stateful upload staging delete");
            let path = self.resolve(session_id);

            match fs::remove_file(&path).await {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Expected in the finalize/GC race — both paths
                    // call delete on a just-finalized session. Benign;
                    // no warn.
                    Ok(())
                }
                Err(e) => {
                    warn!(
                        %session_id,
                        op = "delete",
                        error = %e,
                        "failed to remove staging file"
                    );
                    Err(DomainError::Invariant(format!(
                        "stateful upload staging delete failed: {e}"
                    )))
                }
            }
        })
    }
}

/// Map a staging-root probe I/O failure to the fail-loud boot error.
///
/// Single shared mapper for every step of
/// [`FilesystemStatefulUploadStaging::verify_writable_and_ownable`]
/// (create_dir_all, chmod, probe create/write/flush/cleanup). Folding
/// the six near-identical `.map_err` closures into one helper keeps the
/// gate's error surface DRY and concentrates the formatting into one
/// unit-testable function.
///
/// `stage` is a short, fixed, operator-readable label for which step
/// failed (e.g. `"create_dir_all"`, `"chmod 0o700"`). The message
/// carries the [`std::io::ErrorKind`]; it **never** carries a session
/// id / UUID (cardinality + secondary-symptom enumeration concern).
/// The `staging_root` path itself is logged once at the composition gate
/// (the caller), not embedded here, so this string stays bounded.
fn staging_root_unwritable(stage: &str, e: &std::io::Error) -> DomainError {
    DomainError::Invariant(format!(
        "stateful upload staging root not writable: {stage} failed \
         (io_error_kind={:?}): {e}",
        e.kind()
    ))
}

/// Create a directory and all parents, mapping I/O errors to
/// `DomainError::Invariant` (mirrors the CAS adapter's mapping).
///
/// On Unix, the deepest directory is chmod'd to 0o700 once it exists
/// (ADR 0026 + `docs/architecture/security.md`). `create_dir_all` does
/// not take a mode argument; the chmod must be a separate syscall.
/// Failure is logged but not fatal — chunk files inside are themselves
/// 0o600 via `OpenOptions::mode`, so a laxer dir mode would only expose
/// the existence of session UUIDs, not the chunk bytes.
async fn ensure_dir(path: &Path) -> DomainResult<()> {
    fs::create_dir_all(path).await.map_err(|e| {
        warn!(
            path = %path.display(),
            error = %e,
            "failed to create stateful upload staging directory"
        );
        DomainError::Invariant(format!("stateful upload staging mkdir failed: {e}"))
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).await {
            warn!(
                path = %path.display(),
                error = %e,
                "failed to chmod 0o700 on stateful upload staging directory"
            );
        }
    }

    Ok(())
}

/// Measured length of `file`, as `DomainError::Invariant` on failure.
///
/// Used both before the write (to classify the caller's offset against
/// the file) and after it (to report the physical length rather than a
/// recomputation of what we believe we wrote).
async fn stat_len(file: &fs::File, session_id: Uuid) -> DomainResult<u64> {
    Ok(file
        .metadata()
        .await
        .map_err(|e| {
            warn!(
                %session_id,
                op = "append_at",
                error = %e,
                "failed to stat staging file"
            );
            DomainError::Invariant(format!("stateful upload staging stat failed: {e}"))
        })?
        .len())
}

/// One `read` from the request body, with the adapter's error envelope.
async fn read_or_invariant<R: AsyncRead + Unpin + ?Sized>(
    stream: &mut R,
    buf: &mut [u8],
    session_id: Uuid,
) -> DomainResult<usize> {
    use tokio::io::AsyncReadExt;
    stream.read(buf).await.map_err(|e| {
        warn!(
            %session_id,
            op = "append_at",
            error = %e,
            "failed to read from input stream"
        );
        DomainError::Invariant(format!("stateful upload staging read failed: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::Arc;

    use tokio::io::AsyncReadExt;

    use super::*;

    /// Build a `FilesystemStatefulUploadStaging` rooted in a fresh TempDir.
    fn staging(dir: &tempfile::TempDir) -> FilesystemStatefulUploadStaging {
        FilesystemStatefulUploadStaging::new(dir.path().to_path_buf())
    }

    /// Convenience: boxed `AsyncRead` over an in-memory byte slice.
    fn reader(bytes: &[u8]) -> Box<dyn AsyncRead + Send + Unpin> {
        Box::new(Cursor::new(bytes.to_vec()))
    }

    /// Write `bytes` at the session's current end with a budget of
    /// exactly their length — the shape the OCI use case produces for a
    /// `Content-Length`-framed PATCH that reserved what it then wrote.
    /// Tests whose subject is not the position check itself use this.
    async fn write_tail(
        s: &FilesystemStatefulUploadStaging,
        session: Uuid,
        bytes: &[u8],
    ) -> DomainResult<StagingAppend> {
        let offset = std::fs::metadata(s.resolve(session))
            .map(|m| m.len())
            .unwrap_or(0);
        s.append_at(session, offset, bytes.len() as u64, reader(bytes))
            .await
    }

    /// Append then read back — bytes round-trip through staging.
    #[tokio::test]
    async fn write_then_stream_read_round_trips_single_chunk() {
        let dir = tempfile::tempdir().unwrap();
        let s = staging(&dir);
        let session = Uuid::new_v4();

        let out = write_tail(&s, session, b"hello world").await.unwrap();
        assert_eq!(out.total, 11);
        assert!(!out.truncated);

        let mut r = s.stream_read(session).await.unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"hello world");
    }

    /// Sequential writes at successive offsets accumulate into the same
    /// file.
    #[tokio::test]
    async fn sequential_writes_concatenate_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let s = staging(&dir);
        let session = Uuid::new_v4();

        let t1 = s
            .append_at(session, 0, 8, reader(b"chunk-A|"))
            .await
            .unwrap();
        assert_eq!(t1.total, 8);
        let t2 = s
            .append_at(session, 8, 8, reader(b"chunk-B|"))
            .await
            .unwrap();
        assert_eq!(t2.total, 16);
        let t3 = s
            .append_at(session, 16, 7, reader(b"chunk-C"))
            .await
            .unwrap();
        assert_eq!(t3.total, 23);

        let mut r = s.stream_read(session).await.unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).await.unwrap();
        // Each write names its own offset, so the order is the offsets'
        // order and not the scheduler's.

        assert_eq!(out, b"chunk-A|chunk-B|chunk-C");
    }

    /// The filename uses the UUID's hyphenated lowercase default form
    /// plus a `.part` suffix. Pins the contract the module docstring
    /// makes — the CAS adapter cannot emit a 36-char-plus-`.part` name
    /// via any legitimate code path.
    #[tokio::test]
    async fn staging_file_is_named_session_uuid_dot_part() {
        let dir = tempfile::tempdir().unwrap();
        let s = staging(&dir);
        let session = Uuid::new_v4();

        write_tail(&s, session, b"x").await.unwrap();

        let expected = dir.path().join(format!("{session}.part"));
        assert!(
            expected.exists(),
            "expected staging file at {}; got entries: {:?}",
            expected.display(),
            std::fs::read_dir(dir.path())
                .unwrap()
                .filter_map(Result::ok)
                .map(|e| e.file_name().into_string().unwrap())
                .collect::<Vec<_>>()
        );
    }

    /// Two concurrent `append_at` calls that name the same offset cannot
    /// make the file longer than that offset plus one budget.
    ///
    /// This is the property that replaced `O_APPEND`. Under `O_APPEND`
    /// every write landed at whatever the end happened to be, so two
    /// racers produced the SUM of their payloads — a length no single
    /// caller's record accounted for, and the seed of an unbounded staging
    /// file across retries. Writing at an asserted position makes the
    /// loser overwrite instead of extend.
    ///
    /// The caller is still required to serialise (see the trait's
    /// concurrency contract); this is the backstop for when it does not,
    /// which is why the assertion is on the bound and not on which
    /// payload won.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_writes_at_one_offset_cannot_exceed_the_budget() {
        let dir = tempfile::tempdir().unwrap();
        let s = Arc::new(staging(&dir));
        let session = Uuid::new_v4();

        let a = b"AAAAAAAAAA"; // 10 bytes, distinct content
        let b = b"BBBBBBBBBB"; // 10 bytes, distinct content

        let sa = Arc::clone(&s);
        let sb = Arc::clone(&s);

        let ta = tokio::spawn(async move { sa.append_at(session, 0, 10, reader(a)).await });
        let tb = tokio::spawn(async move { sb.append_at(session, 0, 10, reader(b)).await });

        let (ra, rb) = tokio::join!(ta, tb);
        ra.unwrap().unwrap();
        rb.unwrap().unwrap();

        let mut r = s.stream_read(session).await.unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).await.unwrap();

        assert_eq!(
            out.len(),
            10,
            "two racers at offset 0 must not sum; got {:?}",
            String::from_utf8_lossy(&out)
        );
    }

    /// An offset past the end of the staging file is a gap: the adapter
    /// writes nothing and leaves the length untouched. Filling the hole
    /// would put bytes the client never sent into the middle of the blob.
    #[tokio::test]
    async fn write_past_end_of_staging_refuses_and_leaves_length_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let s = staging(&dir);
        let session = Uuid::new_v4();

        write_tail(&s, session, b"0123456789").await.unwrap();

        let err = s
            .append_at(session, 20, 5, reader(b"abcde"))
            .await
            .expect_err("a write past the end must be refused");
        match err {
            DomainError::Invariant(msg) => {
                assert!(
                    msg.contains("would leave a gap"),
                    "unexpected Invariant message: {msg}"
                );
            }
            other => panic!("expected Invariant, got {other:?}"),
        }

        let len = std::fs::metadata(s.resolve(session)).unwrap().len();
        assert_eq!(len, 10, "a refused write must not change the file");
    }

    /// An offset *short* of the end means the file carries bytes the
    /// caller's record does not account for. The adapter drops that tail
    /// before writing — the record is the authority, so those bytes can
    /// never become content, and leaving them would corrupt the blob the
    /// write completes. This is also what repairs a staging file left
    /// long by an earlier release's append-then-record ordering.
    #[tokio::test]
    async fn write_before_end_of_staging_drops_the_unaccounted_tail() {
        let dir = tempfile::tempdir().unwrap();
        let s = staging(&dir);
        let session = Uuid::new_v4();

        write_tail(&s, session, b"GOOD").await.unwrap();
        // Debris: four more bytes nobody's record knows about.
        write_tail(&s, session, b"junk").await.unwrap();
        assert_eq!(std::fs::metadata(s.resolve(session)).unwrap().len(), 8);

        let out = s
            .append_at(session, 4, 5, reader(b"BYTES"))
            .await
            .expect("a write at the recorded offset must succeed");
        assert_eq!(out.total, 9);

        let mut r = s.stream_read(session).await.unwrap();
        let mut bytes = Vec::new();
        r.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"GOODBYTES", "the junk tail must be gone");
    }

    /// A stream longer than the budget is cut at the budget and reported
    /// as `truncated` — the surplus byte never reaches the file, so the
    /// length cannot exceed `offset + limit`.
    #[tokio::test]
    async fn write_over_budget_reports_truncated_and_keeps_the_surplus_off_disk() {
        let dir = tempfile::tempdir().unwrap();
        let s = staging(&dir);
        let session = Uuid::new_v4();

        let out = s
            .append_at(session, 0, 4, reader(b"0123456789"))
            .await
            .unwrap();
        assert!(out.truncated, "an over-budget body must report truncated");
        assert_eq!(out.total, 4, "the file must stop at the budget");

        let mut r = s.stream_read(session).await.unwrap();
        let mut bytes = Vec::new();
        r.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"0123");
    }

    /// A stream that exactly fills the budget is NOT truncated. The
    /// distinction is the reason `truncated` is a separate field: a cap
    /// that is exactly met is a legal upload, and encoding "there was
    /// more" by letting one extra byte land would put the file over the
    /// very cap the budget expresses.
    #[tokio::test]
    async fn write_exactly_filling_the_budget_is_not_truncated() {
        let dir = tempfile::tempdir().unwrap();
        let s = staging(&dir);
        let session = Uuid::new_v4();

        let out = s.append_at(session, 0, 4, reader(b"0123")).await.unwrap();
        assert!(!out.truncated);
        assert_eq!(out.total, 4);
    }

    /// A body larger than the copy buffer still stops exactly at the
    /// budget — the per-iteration clamp, not the buffer size, is what
    /// bounds the write.
    #[tokio::test]
    async fn write_over_budget_across_multiple_buffer_fills_stops_at_the_budget() {
        let dir = tempfile::tempdir().unwrap();
        let s = staging(&dir);
        let session = Uuid::new_v4();

        let body = vec![7u8; CHUNK_SIZE * 3];
        let limit = (CHUNK_SIZE as u64) + 123;
        let out = s.append_at(session, 0, limit, reader(&body)).await.unwrap();
        assert!(out.truncated);
        assert_eq!(out.total, limit);
        assert_eq!(
            std::fs::metadata(s.resolve(session)).unwrap().len(),
            limit,
            "the measured file length must equal the budget"
        );
    }

    /// `delete` on a session that was never written is `Ok(())`.
    /// Finalize and GC race to delete the same session; a missing file
    /// must not produce an error.
    #[tokio::test]
    async fn delete_missing_session_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        let s = staging(&dir);
        let session = Uuid::new_v4();

        // Never written — file does not exist.
        s.delete(session)
            .await
            .expect("delete must tolerate missing file");
    }

    /// `delete` after a write removes the file and is idempotent.
    #[tokio::test]
    async fn delete_after_write_removes_file_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let s = staging(&dir);
        let session = Uuid::new_v4();

        write_tail(&s, session, b"to-be-deleted").await.unwrap();

        let path = dir.path().join(format!("{session}.part"));
        assert!(path.exists(), "file must exist after the write");

        s.delete(session).await.unwrap();
        assert!(!path.exists(), "file must be gone after delete");

        // Second delete is idempotent.
        s.delete(session).await.unwrap();
    }

    /// `stream_read` on a nonexistent session surfaces `NotFound` with
    /// the entity label `"stateful_upload_staging"`.
    #[tokio::test]
    async fn stream_read_missing_session_returns_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let s = staging(&dir);
        let session = Uuid::new_v4();

        match s.stream_read(session).await {
            Err(DomainError::NotFound {
                entity: "stateful_upload_staging",
                id,
            }) => {
                assert_eq!(id, session.to_string());
            }
            Err(other) => {
                panic!("expected NotFound {{ entity: stateful_upload_staging, .. }}, got {other:?}")
            }
            Ok(_) => panic!("expected NotFound, got Ok"),
        }
    }

    /// A zero-budget write on an empty stream still creates the file
    /// (byte count zero is a legal PATCH body on the OCI wire) and
    /// `stream_read` returns an empty reader.
    #[tokio::test]
    async fn write_empty_stream_creates_zero_byte_file() {
        let dir = tempfile::tempdir().unwrap();
        let s = staging(&dir);
        let session = Uuid::new_v4();

        let out = s.append_at(session, 0, 0, reader(b"")).await.unwrap();
        assert_eq!(out.total, 0);
        assert!(!out.truncated);

        let path = dir.path().join(format!("{session}.part"));
        assert!(path.exists(), "file must exist after zero-byte append");

        let mut r = s.stream_read(session).await.unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).await.unwrap();
        assert!(out.is_empty());
    }

    /// Two different sessions do not collide; each gets its own file.
    #[tokio::test]
    async fn separate_sessions_do_not_collide() {
        let dir = tempfile::tempdir().unwrap();
        let s = staging(&dir);
        let session_a = Uuid::new_v4();
        let session_b = Uuid::new_v4();

        write_tail(&s, session_a, b"session-a-bytes").await.unwrap();
        write_tail(&s, session_b, b"session-b-bytes-longer")
            .await
            .unwrap();

        let mut ra = s.stream_read(session_a).await.unwrap();
        let mut out_a = Vec::new();
        ra.read_to_end(&mut out_a).await.unwrap();
        assert_eq!(out_a, b"session-a-bytes");

        let mut rb = s.stream_read(session_b).await.unwrap();
        let mut out_b = Vec::new();
        rb.read_to_end(&mut out_b).await.unwrap();
        assert_eq!(out_b, b"session-b-bytes-longer");

        // Deleting one does not affect the other.
        s.delete(session_a).await.unwrap();
        let mut rb2 = s.stream_read(session_b).await.unwrap();
        let mut out_b2 = Vec::new();
        rb2.read_to_end(&mut out_b2).await.unwrap();
        assert_eq!(out_b2, b"session-b-bytes-longer");
    }

    /// `append_at` under a root that cannot be created (here: a path
    /// under `/dev/null`, which is a character device, so `mkdir`
    /// refuses) surfaces as `DomainError::Invariant` via `ensure_dir`.
    /// Exercises the `warn!` + `Invariant` arm in `ensure_dir` that
    /// covers every non-happy startup/append filesystem failure.
    #[tokio::test]
    async fn write_under_uncreatable_root_returns_invariant() {
        let root = PathBuf::from("/dev/null/hort-stateful-upload-staging-will-not-exist");
        let s = FilesystemStatefulUploadStaging::new(root);
        let session = Uuid::new_v4();

        match write_tail(&s, session, b"x").await {
            Err(DomainError::Invariant(msg)) => {
                assert!(
                    msg.contains("stateful upload staging mkdir failed")
                        || msg.contains("stateful upload staging"),
                    "unexpected Invariant message: {msg}"
                );
            }
            Err(other) => panic!("expected Invariant, got {other:?}"),
            Ok(_) => panic!("the write must fail when the root is uncreatable"),
        }
    }

    /// `delete` on a path whose `<uuid>.part` entry is a directory
    /// surfaces the non-NotFound IO branch as `DomainError::Invariant`.
    /// `remove_file` on a directory yields `IsADirectory` (or
    /// equivalent), which the adapter must NOT swallow — only NotFound
    /// is swallowed.
    #[tokio::test]
    async fn delete_on_directory_returns_invariant() {
        let dir = tempfile::tempdir().unwrap();
        let s = staging(&dir);
        let session = Uuid::new_v4();

        let path = dir.path().join(format!("{session}.part"));
        std::fs::create_dir_all(&path).unwrap();

        match s.delete(session).await {
            Err(DomainError::Invariant(msg)) => {
                assert!(
                    msg.contains("stateful upload staging delete failed"),
                    "unexpected Invariant message: {msg}"
                );
            }
            Err(other) => panic!("expected Invariant, got {other:?}"),
            Ok(_) => panic!("delete on a directory must fail"),
        }
    }

    // -- list -------------------------------------------------------------
    //
    // Staging-orphan sweep enumeration. The adapter must cap at `max`,
    // skip non-Uuid entries (defensive — the kernel surface lets a tool /
    // test drop a stray file in the staging root), and return at most one
    // entry per `<uuid>.part` file.

    /// Empty staging directory → empty list.
    #[tokio::test]
    async fn list_on_empty_dir_returns_empty_vec() {
        let dir = tempfile::tempdir().unwrap();
        let s = staging(&dir);

        let ids = s.list(10).await.unwrap();
        assert!(ids.is_empty(), "expected empty list, got {ids:?}");
    }

    /// `max` larger than the population → return everything.
    #[tokio::test]
    async fn list_with_fewer_entries_than_max_returns_all() {
        let dir = tempfile::tempdir().unwrap();
        let s = staging(&dir);

        let mut expected: Vec<Uuid> = Vec::new();
        for _ in 0..5 {
            let session = Uuid::new_v4();
            write_tail(&s, session, b"x").await.unwrap();
            expected.push(session);
        }

        let mut ids = s.list(10).await.unwrap();
        assert_eq!(ids.len(), 5, "expected 5 entries, got {}", ids.len());
        ids.sort();
        expected.sort();
        assert_eq!(ids, expected);
    }

    /// `max` smaller than the population → cap at `max` exactly. The
    /// 1500-vs-1000 figure is the production sweep cadence (1000 per
    /// tick) under a synthetic backlog.
    #[tokio::test]
    async fn list_caps_at_max_when_more_entries_exist() {
        let dir = tempfile::tempdir().unwrap();
        let s = staging(&dir);

        for _ in 0..1500 {
            let session = Uuid::new_v4();
            // Use direct file creation rather than `append_at` to keep
            // this test fast — `append_at` does an open + stat + flush per
            // session and 1500 round-trips dwarfs the test runner's
            // patience.
            std::fs::File::create(dir.path().join(format!("{session}.part"))).unwrap();
        }

        let ids = s.list(1000).await.unwrap();
        assert_eq!(
            ids.len(),
            1000,
            "list must cap at max=1000, got {}",
            ids.len()
        );
    }

    /// Non-Uuid entries (e.g. an operator-dropped README) are silently
    /// skipped — the sweep cannot afford to fail on filesystem detritus.
    #[tokio::test]
    async fn list_skips_non_uuid_entries() {
        let dir = tempfile::tempdir().unwrap();
        let s = staging(&dir);

        // Two real sessions.
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        write_tail(&s, a, b"x").await.unwrap();
        write_tail(&s, b, b"y").await.unwrap();

        // Defensive litter — neither is a parseable Uuid filename.
        std::fs::write(dir.path().join("README.txt"), b"hi").unwrap();
        std::fs::write(dir.path().join("not-a-uuid.part"), b"hi").unwrap();
        std::fs::create_dir(dir.path().join("subdir")).unwrap();

        let mut ids = s.list(10).await.unwrap();
        ids.sort();
        let mut expected = vec![a, b];
        expected.sort();
        assert_eq!(ids, expected);
    }

    // ----------------------------------------------------------------------
    // File / directory mode pinning
    //
    // Stateful-upload chunk files are 0o600 (owner rw only) and the
    // staging root is 0o700 (owner rwx only). The modes are pinned by
    // the audit (BSI ORP.4, GDPR Art 32) and are NOT configurable —
    // configurability would be a footgun. A regression to the umask
    // default 0o644 / 0o755 would expose pre-finalization upload bytes
    // to other local readers on a multi-tenant host.
    // (ADR 0026 + `docs/architecture/security.md`)
    // ----------------------------------------------------------------------

    /// `append_at` creates the chunk file at mode 0o600. The chunk holds
    /// pre-finalization bytes (an OCI blob upload mid-PATCH) — leaking
    /// it group/world-readable is a confidentiality breach.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_stateful_upload_chunk_mode_is_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let s = staging(&dir);
        let session = Uuid::new_v4();

        write_tail(&s, session, b"chunk-bytes").await.unwrap();

        let path = dir.path().join(format!("{session}.part"));
        let meta = std::fs::metadata(&path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode,
            0o600,
            "stateful-upload chunk file must be mode 0o600 — got {mode:o} at {}",
            path.display()
        );
    }

    /// The stateful-upload staging root is 0o700 after `new()` runs —
    /// matches the CAS adapter's `.staging/` posture.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_stateful_upload_staging_root_mode_is_0700() {
        use std::os::unix::fs::PermissionsExt;

        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("staging-root");
        let _s = FilesystemStatefulUploadStaging::new(root.clone());

        let meta = std::fs::metadata(&root).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode,
            0o700,
            "stateful-upload staging root must be mode 0o700 — got {mode:o} at {}",
            root.display()
        );
    }

    /// `new` is resilient to a root path that already exists — the
    /// `create_dir_all` call is idempotent.
    #[tokio::test]
    async fn new_is_idempotent_on_existing_root() {
        let dir = tempfile::tempdir().unwrap();
        // First construction creates the root (it already exists via
        // tempdir, but the create_dir_all inside new() is a no-op).
        let _s1 = FilesystemStatefulUploadStaging::new(dir.path().to_path_buf());
        // Second construction is also a no-op.
        let _s2 = FilesystemStatefulUploadStaging::new(dir.path().to_path_buf());
        // Still usable.
        let s3 = FilesystemStatefulUploadStaging::new(dir.path().to_path_buf());
        let session = Uuid::new_v4();
        write_tail(&s3, session, b"x").await.unwrap();
    }

    // ----------------------------------------------------------------------
    // Boot-time writability+ownability gate.
    //
    // The constructor is best-effort (`new()` only `warn!`s on a
    // non-creatable / non-ownable root). That left a non-writable staging
    // root silently dead: `append()` "retries forever" and chunked upload
    // (OCI `docker push`, Git LFS) 5xx's at runtime with NO readiness
    // signal. `verify_writable_and_ownable` adds an explicit, fail-LOUD
    // probe the composition root calls so a non-writable / non-ownable root
    // becomes a fatal boot condition (the pod never enters the Service)
    // instead of a silent degradation — the same fail-closed/loud discipline
    // (ADR 0007).
    //
    // `verify_writable_and_ownable()` is an *inherent* method, NOT a
    // `StatefulUploadStagingPort` trait method — the trait signature is
    // unchanged; composition calls it on the concrete adapter, mirroring the
    // `KubernetesSecretWriterImpl::try_in_cluster()` fatal-boot precedent.
    // ----------------------------------------------------------------------

    /// Happy path: a writable, owner-ownable tempdir passes the gate.
    #[tokio::test]
    async fn verify_writable_and_ownable_passes_on_writable_root() {
        let dir = tempfile::tempdir().unwrap();
        let s = staging(&dir);
        s.verify_writable_and_ownable()
            .await
            .expect("a writable tempdir root must pass the boot gate");
    }

    /// A staging root that cannot be created (a path under `/dev/null`,
    /// a char device, so `mkdir` refuses — the read-only-rootfs EROFS
    /// analogue) must surface a `DomainError::Invariant` from the boot
    /// gate, instead of the constructor's silent `warn!`. Composition
    /// turns this `Err` into a fatal boot error (pod stays out of
    /// Service).
    #[tokio::test]
    async fn verify_writable_and_ownable_fails_on_uncreatable_root() {
        let root = PathBuf::from("/dev/null/hort-f5-staging-root-cannot-exist");
        let s = FilesystemStatefulUploadStaging::new(root);

        match s.verify_writable_and_ownable().await {
            Err(DomainError::Invariant(msg)) => {
                assert!(
                    msg.contains("stateful upload staging root not writable")
                        || msg.contains("stateful upload staging"),
                    "unexpected Invariant message: {msg}"
                );
            }
            Err(other) => panic!("expected Invariant, got {other:?}"),
            Ok(()) => panic!(
                "boot gate must FAIL on an uncreatable staging root \
                 (was a silent warn-then-retry-forever)"
            ),
        }
    }

    /// A staging-root *path that is a regular file* (operator pointed
    /// `HORT_STATEFUL_UPLOAD_STAGING_DIR` at a file, or a mount shadowed
    /// it) must fail the boot gate at `create_dir_all` — chunked upload
    /// can never function against a non-directory root. This exercises
    /// the step-(1) error arm with a different io-error kind than the
    /// `/dev/null` parent case, and is fully deterministic and
    /// root-independent (a regular file is not a directory regardless
    /// of EUID — unlike a DAC write-bit, which root bypasses, so this
    /// negative is observable even in a root CI container).
    ///
    /// Note: a *locally-chmod-able* 0o500 dir is intentionally NOT a
    /// failure case — the gate (like `new()`'s post-create chmod) heals
    /// the mode to 0o700, which is the correct outcome. The genuine
    /// failure scenario is a *read-only filesystem* (EROFS) where chmod
    /// and file-create themselves fail; that is covered by
    /// `verify_writable_and_ownable_fails_on_uncreatable_root` (the
    /// `/dev/null/...` EROFS analogue).
    #[tokio::test]
    async fn verify_writable_and_ownable_fails_when_root_is_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let root_file = dir.path().join("staging-is-a-file");
        std::fs::write(&root_file, b"not a directory").unwrap();

        let s = FilesystemStatefulUploadStaging::new(root_file);
        match s.verify_writable_and_ownable().await {
            Err(DomainError::Invariant(msg)) => {
                assert!(
                    msg.contains("stateful upload staging root not writable")
                        || msg.contains("stateful upload staging"),
                    "unexpected Invariant message: {msg}"
                );
            }
            Err(other) => panic!("expected Invariant, got {other:?}"),
            Ok(()) => panic!("boot gate must FAIL when the staging root path is a regular file"),
        }
    }

    /// The shared boot-gate error mapper builds a `DomainError::Invariant`
    /// that names the failing step + the io-error kind, and carries NO
    /// session id / UUID (cardinality + secondary-symptom enumeration
    /// concern). Driven with a synthetic `io::Error` so the formatting
    /// path is covered deterministically without needing root or a
    /// fault-injection layer (the per-step `.map_err` call sites are
    /// otherwise unportable to trigger individually).
    #[test]
    fn staging_root_unwritable_formats_step_and_kind_without_uuid() {
        let e = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "EACCES (synthetic)");
        let mapped = staging_root_unwritable("chmod 0o700", &e);
        match mapped {
            DomainError::Invariant(msg) => {
                assert!(
                    msg.contains("stateful upload staging root not writable"),
                    "missing the fail-loud prefix: {msg}"
                );
                assert!(msg.contains("chmod 0o700"), "missing the step label: {msg}");
                assert!(
                    msg.contains("PermissionDenied"),
                    "missing the io_error_kind: {msg}"
                );
                // Cardinality / secondary-symptom guard: a UUID's
                // canonical hyphenated form never appears in the gate
                // error. (We can't enumerate every UUID; assert the
                // structural property — no `.part`, no hyphen-grouped
                // 8-4-4-4-12 hex run is constructed here by design.)
                assert!(
                    !msg.contains(".part"),
                    "gate error must not reference a staging filename: {msg}"
                );
            }
            other => panic!("expected Invariant, got {other:?}"),
        }
    }

    /// The boot gate leaves no probe litter behind on the happy path —
    /// the staging root is empty after a successful verify (the sweep
    /// must not see a phantom non-`.part` entry).
    #[tokio::test]
    async fn verify_writable_and_ownable_leaves_no_litter() {
        let dir = tempfile::tempdir().unwrap();
        let s = staging(&dir);
        s.verify_writable_and_ownable().await.unwrap();

        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name())
            .collect();
        assert!(
            entries.is_empty(),
            "boot gate must not leave a probe file behind; found {entries:?}"
        );
    }
}
