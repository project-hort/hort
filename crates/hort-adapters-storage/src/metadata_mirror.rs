//! `MetadataMirrorStore` impls (ADR 0026).
//!
//! Two backends mirroring the CAS [`StoragePort`](super::filesystem) pair:
//! a filesystem tree and an `object_store`-backed blob store. Unlike CAS,
//! the mirror is logical-keyed + overwrite (metadata is mutable), so there
//! is no hashing / dedup / refcount machinery here.
//!
//! Correctness invariants beyond the CAS adapters:
//!
//! - **Mode 0600.** Mirror blobs hold authenticated-upstream metadata; the
//!   filesystem backend creates the staged + final file mode `0o600` so they
//!   are never world/group readable (ADR 0026 + `docs/architecture/security.md`).
//! - **Traversal defense-in-depth.** The package key segment is
//!   upstream-influenced and — unlike CAS hash keys — is not regex-checked,
//!   so [`validate_key`] rejects a key whose `/`-split segments are anything
//!   but plain names (→ [`DomainError::Validation`]) before any path join.
//! - **The staging area is not addressable.** See [`RESERVED_SEGMENT`].
//! - **A body carries its own digest.** See [the frame](frame_header).
//!
//! # What the recorded digest buys, and what it does not
//!
//! The mirror is the authority for a **verified** pull. When an upstream
//! fetch fails and no projection is cached, the npm / PyPI / cargo index
//! paths re-project from the mirror, and the per-version `shasum` /
//! `integrity` / checksum in that projection is exactly what the
//! subsequent artifact pull verifies the downloaded bytes against. A
//! mirror body nobody checks therefore makes that pull's verification
//! circular: whoever alters the body also chooses the digest it is
//! compared to.
//!
//! So `put` records the body's SHA-256 and `get` refuses a body that does
//! not match it. What that establishes is **"these are the bytes some
//! `put` wrote, whole and unaltered"** — integrity at rest, against
//! corruption, truncation, a half-written file and alteration after the
//! fact. It establishes nothing about whether the upstream that produced
//! those bytes was honest; that is a different question and this is not
//! its answer.
//!
//! It also does not defend against an adversary with write access to the
//! mirror store itself, and no scheme available to this port can: the
//! mirror is read precisely when every other copy of the authority is
//! gone (cold projection cache, unreachable upstream), so the digest has
//! to live where the mirror lives. Raising that bar means recording the
//! digest somewhere outside the store, which is a different decision with
//! its own cost to the air-gapped path.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use futures::StreamExt;
use object_store::{ObjectStore, ObjectStoreExt};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio_util::io::StreamReader;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::metadata_mirror_store::MetadataMirrorStore;
use hort_domain::ports::BoxFuture;
use hort_domain::types::ContentHash;

use crate::integrity::VerifyingReader;
use crate::metrics::{emit_mirror_integrity_failure, values};

/// Key segment reserved for the mirror's own bookkeeping, and refused by
/// [`validate_key`] wherever it appears.
///
/// The filesystem backend stages every write under
/// `<root>/<RESERVED_SEGMENT>/<STAGING_SUBDIR>/` and renames into place.
/// Staging has to be under the same root to keep the rename atomic (same
/// filesystem), and the mirror root is the whole addressable keyspace —
/// `resolve` maps any key straight onto `<root>/<key>` — so without this
/// reservation a staged file *is* a readable key: a `get` on it serves a
/// half-written body while the write runs, and an orphan left by a crash
/// serves forever.
///
/// Reserved in **both** backends even though only the filesystem one
/// stages. Which keys are legal is a property of the port, not of the
/// deployment's storage choice; a key that resolves on S3 and is refused
/// on disk would make switching backends change what is addressable.
const RESERVED_SEGMENT: &str = ".hort-internal";

/// Subdirectory of [`RESERVED_SEGMENT`] holding in-flight writes.
const STAGING_SUBDIR: &str = "tmp";

/// Frame header prefix. Fixed-width and version-tagged so a read can tell
/// "no digest was ever recorded here" from "the digest does not match",
/// and so a future frame revision is a distinguishable value rather than
/// a guess about the layout.
const FRAME_MAGIC: &[u8] = b"hort-mirror-sha256-v1:";

/// Lowercase-hex SHA-256 width.
const DIGEST_HEX_LEN: usize = 64;

/// Total frame-header width: magic, digest, newline. Fixed, so a read is
/// one `read_exact` and the body begins at a known offset.
const FRAME_LEN: usize = FRAME_MAGIC.len() + DIGEST_HEX_LEN + 1;

/// The frame header for `digest_hex`, written ahead of the body bytes.
///
/// The digest travels **in the same object as the bytes it describes**,
/// rather than in a sidecar key or a companion file, and that is a
/// deliberate trade:
///
/// - One object means one atomic write. The filesystem backend renames a
///   single staged file; the object-store backend issues a single `put`
///   (it has no rename at all). A body and a separately-stored digest
///   cannot be committed together on either backend, and every ordering
///   leaves a window where they describe different things — after which
///   the key is unservable until its next refresh. For an air-gapped
///   deployment there is no next refresh.
/// - It is consistent under concurrent writes. Two replicas refreshing
///   the same package land one whole frame or the other; a body and a
///   sidecar can interleave into a pair that never matched.
/// - Restoring one body file from a backup restores its digest with it.
///
/// What the in-band placement does *not* buy is defence against an
/// adversary who can rewrite the file, since they can rewrite the header
/// too. Neither does a sidecar in the same volume under the same
/// credentials; see the module doc for why nothing this port can hold
/// does.
fn frame_header(digest_hex: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(FRAME_LEN);
    out.extend_from_slice(FRAME_MAGIC);
    out.extend_from_slice(digest_hex.as_bytes());
    out.push(b'\n');
    debug_assert_eq!(out.len(), FRAME_LEN);
    out
}

/// A placeholder frame of the right width, written before the body so the
/// real digest — which is not knowable until the last byte has streamed
/// through — can be patched into the slot afterwards without buffering
/// the body (ADR 0026: metadata bodies reach tens of MiB).
fn placeholder_frame_header() -> Vec<u8> {
    frame_header(&"0".repeat(DIGEST_HEX_LEN))
}

/// The digest recorded in `raw`, which must be exactly [`FRAME_LEN`]
/// bytes read from the head of a stored body.
fn parse_frame_header(raw: &[u8], key: &str) -> DomainResult<ContentHash> {
    if !raw.starts_with(FRAME_MAGIC) {
        return Err(DomainError::Invariant(format!(
            "metadata mirror body at {key} carries no recorded digest: \
             the frame header is missing or unrecognised"
        )));
    }
    let hex = &raw[FRAME_MAGIC.len()..FRAME_MAGIC.len() + DIGEST_HEX_LEN];
    std::str::from_utf8(hex)
        .map_err(|_| ())
        .and_then(|hex| hex.parse::<ContentHash>().map_err(|_| ()))
        .map_err(|()| {
            DomainError::Invariant(format!(
                "metadata mirror body at {key} has a malformed frame header digest"
            ))
        })
}

/// Reject any key that is not a `/`-joined sequence of plain names.
///
/// `..` is the traversal defence the upstream-influenced package segment
/// has always needed. `.`, an empty segment and [`RESERVED_SEGMENT`] are
/// what make "a key never resolves into the staging area" an airtight
/// statement rather than an approximate one: refusing only a *leading*
/// `.hort-internal` would still admit `./.hort-internal/…`, and refusing
/// only `..` would admit a leading `/`, which `Path::join` resolves by
/// discarding the root entirely.
///
/// No real key is affected: every key is built by
/// `hort_domain::ports::metadata_mirror_store::mirror_key`, whose
/// segments are a format name, a mapping UUID and a url-encoded package
/// path — none of which can be empty, a dot, or the reserved name.
fn validate_key(key: &str) -> DomainResult<()> {
    for segment in key.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." || segment == RESERVED_SEGMENT {
            return Err(DomainError::Validation(format!(
                "metadata mirror key has an illegal path segment {segment:?}: {key}"
            )));
        }
    }
    Ok(())
}

/// Filesystem-backed mirror. `key` is a `/`-delimited logical key; it maps
/// to `<root>/<key>` with parent dirs created on put. Overwrite via
/// write-staged-file + rename (atomic). Files are created mode `0o600`.
pub struct FilesystemMetadataMirror {
    root: PathBuf,
}

impl FilesystemMetadataMirror {
    /// Construct a filesystem mirror rooted at `root` (a `meta-mirror/`
    /// subtree is created lazily on the first put).
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// Validate `key`, then resolve it to `<root>/<key>`.
    fn resolve(&self, key: &str) -> DomainResult<PathBuf> {
        validate_key(key)?;
        Ok(self.root.join(key))
    }

    /// A fresh, unique path in the non-addressable staging area.
    ///
    /// Unique per call, not derived from the key: the previous name was
    /// `path.with_extension("tmp")`, and because `with_extension`
    /// *replaces* an existing extension, two keys differing only in
    /// extension (`flask.json` / `flask.html` — the PyPI simple index
    /// serves both) staged through one file, wrote into each other, and
    /// each rename could move the other's half-written body onto its
    /// key's path.
    fn staging_path(&self) -> PathBuf {
        self.root
            .join(RESERVED_SEGMENT)
            .join(STAGING_SUBDIR)
            .join(format!("{}.tmp", uuid::Uuid::new_v4()))
    }
}

/// Stream `body` into `file`, hashing as it flows, and return the
/// lowercase-hex SHA-256. No whole-body buffer (ADR 0026).
async fn copy_hashing(
    body: &mut (dyn AsyncRead + Send + Unpin),
    file: &mut tokio::fs::File,
) -> std::io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let read = body.read(&mut buf).await?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
        file.write_all(&buf[..read]).await?;
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Write the framed body to `staged` and rename it onto `path`.
///
/// Split out so [`FilesystemMetadataMirror::put`] can unlink the staged
/// file on every failure path without duplicating the cleanup per step.
async fn write_staged_frame(
    staged: &Path,
    path: &Path,
    body: &mut (dyn AsyncRead + Send + Unpin),
) -> DomainResult<()> {
    // Create the staged file mode 0600 atomically with creation. The
    // rename below preserves the inode + mode, so the final mirror blob
    // inherits 0600 without a follow-up chmod. On non-Unix the mode is
    // silently ignored (Windows ACL semantics differ; the project's
    // primary target is Linux). `tokio::fs::OpenOptions::mode` is an
    // inherent method (no `std::os::unix::fs::OpenOptionsExt` import
    // needed) — mirrors the CAS `FilesystemStorage::put` site.
    let mut open_opts = tokio::fs::OpenOptions::new();
    open_opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        open_opts.mode(0o600);
    }
    let mut file = open_opts
        .open(staged)
        .await
        .map_err(|e| DomainError::Invariant(format!("mirror create: {e}")))?;

    // Reserve the frame slot, stream the body past it, then patch the
    // real digest in. The digest is only known at the last byte, and
    // buffering the body to learn it first is what ADR 0026 forbids.
    file.write_all(&placeholder_frame_header())
        .await
        .map_err(|e| DomainError::Invariant(format!("mirror frame reserve: {e}")))?;
    let digest_hex = copy_hashing(body, &mut file)
        .await
        .map_err(|e| DomainError::Invariant(format!("mirror write: {e}")))?;
    file.seek(std::io::SeekFrom::Start(0))
        .await
        .map_err(|e| DomainError::Invariant(format!("mirror frame seek: {e}")))?;
    file.write_all(&frame_header(&digest_hex))
        .await
        .map_err(|e| DomainError::Invariant(format!("mirror frame write: {e}")))?;

    // Flush to disk before rename for crash safety, raising the error
    // rather than discarding it — consistent with the CAS sibling
    // (`FilesystemStorage::put`, filesystem.rs sync_all). A silent
    // `.ok()` would let a failed fsync rename a torn file into place.
    file.sync_all()
        .await
        .map_err(|e| DomainError::Invariant(format!("mirror sync: {e}")))?;
    drop(file);
    tokio::fs::rename(staged, path)
        .await
        .map_err(|e| DomainError::Invariant(format!("mirror rename: {e}")))
}

impl MetadataMirrorStore for FilesystemMetadataMirror {
    fn put(
        &self,
        key: &str,
        mut body: Box<dyn AsyncRead + Send + Unpin>,
    ) -> BoxFuture<'_, DomainResult<()>> {
        let path = self.resolve(key);
        let staged = self.staging_path();
        Box::pin(async move {
            let path = path?;
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .map_err(|e| DomainError::Invariant(format!("mirror mkdir: {e}")))?;
            }
            if let Some(parent) = staged.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .map_err(|e| DomainError::Invariant(format!("mirror staging mkdir: {e}")))?;
            }

            let outcome = write_staged_frame(&staged, &path, body.as_mut()).await;
            if outcome.is_err() {
                // The staged file is unreachable through the key
                // interface, so leaving it behind is a disk leak rather
                // than a correctness problem — but a leak with no reaper
                // is still a leak, and the failing caller is the only
                // party that knows this name. Best-effort: a cleanup
                // failure must not mask the write failure being
                // reported.
                if let Err(e) = tokio::fs::remove_file(&staged).await {
                    tracing::debug!(error = %e, "mirror staging cleanup failed (non-fatal)");
                }
            }
            outcome
        })
    }

    fn get(
        &self,
        key: &str,
    ) -> BoxFuture<'_, DomainResult<Option<Box<dyn AsyncRead + Send + Unpin>>>> {
        let path = self.resolve(key);
        let key = key.to_string();
        Box::pin(async move {
            let path = path?;
            let mut file = match tokio::fs::File::open(&path).await {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => return Err(DomainError::Invariant(format!("mirror open: {e}"))),
            };
            let expected = read_frame(&mut file, &key, values::BACKEND_FILESYSTEM).await?;
            Ok(Some(verified(file, expected, values::BACKEND_FILESYSTEM)))
        })
    }

    fn delete(&self, key: &str) -> BoxFuture<'_, DomainResult<()>> {
        let path = self.resolve(key);
        Box::pin(async move {
            let path = path?;
            match tokio::fs::remove_file(&path).await {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(DomainError::Invariant(format!("mirror delete: {e}"))),
            }
        })
    }
}

/// Read and parse the frame header sitting at the head of a stored body,
/// leaving `reader` positioned at the first body byte.
///
/// A body too short to hold a header, or one whose header does not parse,
/// has no recorded digest — so there is nothing to verify it against and
/// it is refused. Fail-closed on purpose: the alternative ("serve it when
/// no digest was recorded") is a bypass anyone who can write the file
/// reaches by deleting the header, and it is the degraded-authority
/// fallback this codebase rules out by policy.
async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    key: &str,
    backend: &'static str,
) -> DomainResult<ContentHash> {
    let mut header = [0u8; FRAME_LEN];
    if let Err(e) = reader.read_exact(&mut header).await {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            emit_mirror_integrity_failure(backend, values::REASON_UNFRAMED);
            tracing::warn!(
                key = %key,
                "metadata mirror body is shorter than a frame header; refusing it. \
                 A body written before digest framing reads this way until its next \
                 upstream refresh rewrites it."
            );
            return Err(DomainError::Invariant(format!(
                "metadata mirror body at {key} is too short to carry a frame header"
            )));
        }
        return Err(DomainError::Invariant(format!("mirror read: {e}")));
    }
    match parse_frame_header(&header, key) {
        Ok(expected) => Ok(expected),
        Err(e) => {
            emit_mirror_integrity_failure(backend, values::REASON_UNFRAMED);
            tracing::warn!(
                key = %key,
                "metadata mirror body carries no recorded digest; refusing it. \
                 A body written before digest framing reads this way until its next \
                 upstream refresh rewrites it."
            );
            Err(e)
        }
    }
}

/// Wrap a body reader, already positioned past its frame header, in the
/// same streaming verifier the CAS reads go through: the digest
/// accumulates as bytes flow and the read fails at EOF rather than
/// reporting a clean end when the body does not hash to `expected`.
fn verified<R: AsyncRead + Send + Unpin + 'static>(
    reader: R,
    expected: ContentHash,
    backend: &'static str,
) -> Box<dyn AsyncRead + Send + Unpin> {
    Box::new(VerifyingReader::new(
        reader,
        expected,
        Some(Box::new(move || {
            emit_mirror_integrity_failure(backend, values::REASON_DIGEST_MISMATCH)
        })),
    ))
}

/// Object-store-backed mirror (S3/GCS/Azure/in-memory). Holds the same
/// `Arc<dyn ObjectStore>` the CAS [`ObjectStoreStorage`](super::object_store_backend)
/// uses; the logical `key` maps directly to an `object_store` path. Overwrite
/// is the object store's native put semantics (last write wins).
pub struct ObjectStoreMetadataMirror {
    store: Arc<dyn ObjectStore>,
    backend: &'static str,
}

impl ObjectStoreMetadataMirror {
    /// Construct an object-store mirror over `store`. `backend` is the
    /// metric label value (`s3` / `gcs` / `azure` / `memory`), passed in
    /// by the composition root the same way
    /// [`ObjectStoreStorage`](super::object_store_backend) takes it — the
    /// `Arc<dyn ObjectStore>` itself does not say which backend it is.
    pub fn new(store: Arc<dyn ObjectStore>, backend: &'static str) -> Self {
        Self { store, backend }
    }

    /// Validate `key`, then map it to an object-store path.
    fn resolve(&self, key: &str) -> DomainResult<object_store::path::Path> {
        validate_key(key)?;
        Ok(object_store::path::Path::from(key))
    }
}

impl MetadataMirrorStore for ObjectStoreMetadataMirror {
    fn put(
        &self,
        key: &str,
        mut body: Box<dyn AsyncRead + Send + Unpin>,
    ) -> BoxFuture<'_, DomainResult<()>> {
        let path = self.resolve(key);
        Box::pin(async move {
            let path = path?;
            // BOUNDED-BODY ASSUMPTION: the body handed to this port is the
            // small, already-capped upstream metadata projection's source
            // (npm packument / PyPI simple-index / cargo index — bounded by
            // the per-value + whole-body projector caps upstream of here),
            // NOT the unbounded raw artifact bytes. Buffer-then-`put` keeps
            // overwrite atomic (object stores have no rename) without the
            // multipart staging the CAS path needs for multi-GB artifacts.
            // If a future caller ever routes the raw artifact stream through
            // this port, this `Vec` buffer becomes a memory hazard (a 2 GB
            // artifact = 2 GB resident) — that caller MUST switch to
            // `store.put_multipart` (as `ObjectStoreStorage::put` does) and
            // stream, not buffer.
            //
            // The frame is reserved up front and patched after hashing so
            // the object is written once, exactly as the filesystem
            // backend does it — prepending afterwards would move the whole
            // body.
            let mut buf = placeholder_frame_header();
            tokio::io::copy(&mut body, &mut buf)
                .await
                .map_err(|e| DomainError::Invariant(format!("mirror read: {e}")))?;
            let digest_hex = hex::encode(Sha256::digest(&buf[FRAME_LEN..]));
            buf[..FRAME_LEN].copy_from_slice(&frame_header(&digest_hex));
            self.store
                .put(&path, bytes::Bytes::from(buf).into())
                .await
                .map_err(|e| DomainError::Invariant(format!("mirror put: {e}")))?;
            Ok(())
        })
    }

    fn get(
        &self,
        key: &str,
    ) -> BoxFuture<'_, DomainResult<Option<Box<dyn AsyncRead + Send + Unpin>>>> {
        let path = self.resolve(key);
        let key = key.to_string();
        let backend = self.backend;
        Box::pin(async move {
            let path = path?;
            match self.store.get(&path).await {
                Ok(result) => {
                    let byte_stream = result
                        .into_stream()
                        .map(|chunk| chunk.map_err(std::io::Error::other));
                    let mut reader = StreamReader::new(byte_stream);
                    let expected = read_frame(&mut reader, &key, backend).await?;
                    Ok(Some(verified(reader, expected, backend)))
                }
                Err(object_store::Error::NotFound { .. }) => Ok(None),
                Err(e) => Err(DomainError::Invariant(format!("mirror get: {e}"))),
            }
        })
    }

    fn delete(&self, key: &str) -> BoxFuture<'_, DomainResult<()>> {
        let path = self.resolve(key);
        Box::pin(async move {
            let path = path?;
            match self.store.delete(&path).await {
                Ok(()) => Ok(()),
                Err(object_store::Error::NotFound { .. }) => Ok(()),
                Err(e) => Err(DomainError::Invariant(format!("mirror delete: {e}"))),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SHA-256 of b"hello world".
    const HELLO_WORLD_SHA256: &str =
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    /// The header is fixed-width, so a read is one `read_exact` and the
    /// body starts at a known offset. A change to the magic that moved
    /// that width without the constant tracking it would make every read
    /// slice the wrong bytes.
    #[test]
    fn the_frame_header_is_exactly_frame_len_bytes() {
        assert_eq!(frame_header(HELLO_WORLD_SHA256).len(), FRAME_LEN);
        assert_eq!(placeholder_frame_header().len(), FRAME_LEN);
    }

    /// A header round-trips to the digest it recorded.
    #[test]
    fn a_written_header_parses_back_to_its_digest() {
        let raw = frame_header(HELLO_WORLD_SHA256);
        let parsed = parse_frame_header(&raw, "k").expect("round-trip");
        assert_eq!(parsed.as_ref(), HELLO_WORLD_SHA256);
    }

    /// The placeholder is a well-formed header carrying a digest no body
    /// can hash to, so a body whose write died between reserving the slot
    /// and patching it reads as a mismatch rather than as a valid frame.
    /// (That body is unreachable anyway — it never left staging — but the
    /// placeholder must not be a frame that *passes*.)
    #[test]
    fn the_placeholder_digest_is_not_a_digest_any_body_has() {
        let parsed = parse_frame_header(&placeholder_frame_header(), "k").expect("well-formed");
        assert_eq!(parsed.as_ref(), "0".repeat(DIGEST_HEX_LEN));
    }

    /// Bytes that are not a frame have no recorded digest.
    #[test]
    fn a_body_without_the_magic_has_no_recorded_digest() {
        let raw = vec![b'{'; FRAME_LEN];
        let err = parse_frame_header(&raw, "meta-mirror/npm/m/p").expect_err("refused");
        assert!(
            matches!(&err, DomainError::Invariant(m) if m.contains("frame header")),
            "got: {err:?}"
        );
    }

    /// A frame whose digest field is not 64 lowercase hex characters is
    /// malformed, not merely mismatched — there is nothing to verify
    /// against, so it is refused the same way an absent frame is.
    #[test]
    fn a_frame_with_a_malformed_digest_is_refused() {
        let mut raw = frame_header(HELLO_WORLD_SHA256);
        raw[FRAME_MAGIC.len()] = b'Z';
        let err = parse_frame_header(&raw, "k").expect_err("refused");
        assert!(
            matches!(&err, DomainError::Invariant(m) if m.contains("malformed")),
            "got: {err:?}"
        );
    }

    /// Every segment shape that would let a key resolve outside its own
    /// place in the keyspace — up and out of the root, into the root
    /// itself, or into the staging area.
    #[test]
    fn illegal_key_segments_are_refused() {
        for key in [
            "meta-mirror/npm/m/../../../etc/passwd",
            "meta-mirror/npm/m/..",
            "..",
            "./meta-mirror/npm/m/p",
            "meta-mirror/./npm/m/p",
            "",
            "/meta-mirror/npm/m/p",
            "meta-mirror//npm/m/p",
            ".hort-internal/tmp/x",
            "./.hort-internal/tmp/x",
            "meta-mirror/npm/.hort-internal/p",
        ] {
            assert!(
                matches!(validate_key(key), Err(DomainError::Validation(_))),
                "{key:?} must be refused"
            );
        }
    }

    /// The keys the port actually receives are legal. `mirror_key`'s own
    /// output for each format family, including a scoped npm name (the
    /// url-encoded `%2f` is one segment, not two) and a cargo sharded
    /// path (which is genuinely multi-segment).
    #[test]
    fn real_mirror_keys_are_accepted() {
        use hort_domain::ports::metadata_mirror_store::mirror_key;

        let mapping = "11111111-1111-1111-1111-111111111111";
        for key in [
            mirror_key("npm", mapping, "express"),
            mirror_key("npm", mapping, "@types%2fnode"),
            mirror_key("pypi", mapping, "flask"),
            mirror_key("cargo", mapping, "se/rd/serde"),
            mirror_key("cargo", mapping, "1/a"),
        ] {
            validate_key(&key).unwrap_or_else(|e| panic!("{key} must be legal: {e:?}"));
        }
    }

    /// The staging path lands inside the reserved subtree — which
    /// `validate_key` refuses — and is different on every call. Both
    /// halves are the fix for the shared `with_extension("tmp")` name:
    /// uniqueness stops two writes colliding, the reserved location stops
    /// either one being readable as a key.
    #[test]
    fn staging_paths_are_unique_and_inside_the_reserved_subtree() {
        let mirror = FilesystemMetadataMirror::new(PathBuf::from("/srv/hort"));
        let a = mirror.staging_path();
        let b = mirror.staging_path();
        assert_ne!(a, b, "a staging name must not be reused");

        let reserved = PathBuf::from("/srv/hort")
            .join(RESERVED_SEGMENT)
            .join(STAGING_SUBDIR);
        assert!(a.starts_with(&reserved), "{a:?} must be under {reserved:?}");
        assert!(b.starts_with(&reserved));
    }
}
