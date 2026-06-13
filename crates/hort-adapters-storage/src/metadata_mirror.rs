//! `MetadataMirrorStore` impls (ADR 0026).
//!
//! Two backends mirroring the CAS [`StoragePort`](super::filesystem) pair:
//! a filesystem tree and an `object_store`-backed blob store. Unlike CAS,
//! the mirror is logical-keyed + overwrite (metadata is mutable), so there
//! is no hashing / dedup / refcount machinery here.
//!
//! Two correctness invariants beyond the CAS adapters:
//! - **Mode 0600.** Mirror blobs hold authenticated-upstream metadata; the
//!   filesystem backend creates the temp + final file mode `0o600` so they
//!   are never world/group readable (ADR 0026 + `docs/architecture/security.md`).
//! - **Traversal defense-in-depth.** The package key segment is
//!   upstream-influenced and — unlike CAS hash keys — is not regex-checked,
//!   so [`reject_traversal`] rejects any key whose `/`-split segments
//!   contain `..` (→ [`DomainError::Validation`]) before any path join.

use std::path::PathBuf;
use std::sync::Arc;

use futures::StreamExt;
use object_store::{ObjectStore, ObjectStoreExt};
use tokio::io::AsyncRead;
use tokio_util::io::StreamReader;

use hort_domain::error::{DomainError, DomainResult};
use hort_domain::ports::metadata_mirror_store::MetadataMirrorStore;
use hort_domain::ports::BoxFuture;

/// Reject any key whose `/`-split segments contain a `..` traversal
/// component. The package segment is upstream-influenced (see module doc),
/// so we fail-closed before joining it onto the mirror root / object path.
fn reject_traversal(key: &str) -> DomainResult<()> {
    if key.split('/').any(|seg| seg == "..") {
        return Err(DomainError::Validation(format!(
            "metadata mirror key contains a traversal component: {key}"
        )));
    }
    Ok(())
}

/// Filesystem-backed mirror. `key` is a `/`-delimited logical key; it maps
/// to `<root>/<key>` with parent dirs created on put. Overwrite via
/// write-temp + rename (atomic). Files are created mode `0o600` (F-44).
pub struct FilesystemMetadataMirror {
    root: PathBuf,
}

impl FilesystemMetadataMirror {
    /// Construct a filesystem mirror rooted at `root` (a `meta-mirror/`
    /// subtree is created lazily on the first put).
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// Validate `key` for traversal, then resolve it to `<root>/<key>`.
    fn resolve(&self, key: &str) -> DomainResult<PathBuf> {
        reject_traversal(key)?;
        Ok(self.root.join(key))
    }
}

impl MetadataMirrorStore for FilesystemMetadataMirror {
    fn put(
        &self,
        key: &str,
        mut body: Box<dyn AsyncRead + Send + Unpin>,
    ) -> BoxFuture<'_, DomainResult<()>> {
        let path = self.resolve(key);
        Box::pin(async move {
            let path = path?;
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .map_err(|e| DomainError::Invariant(format!("mirror mkdir: {e}")))?;
            }
            let tmp = path.with_extension("tmp");

            // F-44: create the temp file mode 0600 atomically with
            // creation. The rename below preserves the inode + mode, so
            // the final mirror blob inherits 0600 without a follow-up
            // chmod. On non-Unix the mode is silently ignored (Windows
            // ACL semantics differ; the project's primary target is Linux).
            // `tokio::fs::OpenOptions::mode` is an inherent method (no
            // `std::os::unix::fs::OpenOptionsExt` import needed) — mirrors
            // the CAS `FilesystemStorage::put` site (filesystem.rs:226-231).
            let mut open_opts = tokio::fs::OpenOptions::new();
            open_opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                open_opts.mode(0o600);
            }
            let mut f = open_opts
                .open(&tmp)
                .await
                .map_err(|e| DomainError::Invariant(format!("mirror create: {e}")))?;

            tokio::io::copy(&mut body, &mut f)
                .await
                .map_err(|e| DomainError::Invariant(format!("mirror write: {e}")))?;
            // Flush to disk before rename for crash safety, raising the
            // error rather than discarding it — consistent with the CAS
            // sibling (`FilesystemStorage::put`, filesystem.rs sync_all).
            // A silent `.ok()` would let a failed fsync rename a torn file
            // into place.
            f.sync_all()
                .await
                .map_err(|e| DomainError::Invariant(format!("mirror sync: {e}")))?;
            tokio::fs::rename(&tmp, &path)
                .await
                .map_err(|e| DomainError::Invariant(format!("mirror rename: {e}")))
        })
    }

    fn get(
        &self,
        key: &str,
    ) -> BoxFuture<'_, DomainResult<Option<Box<dyn AsyncRead + Send + Unpin>>>> {
        let path = self.resolve(key);
        Box::pin(async move {
            let path = path?;
            match tokio::fs::File::open(&path).await {
                Ok(f) => Ok(Some(Box::new(f) as Box<dyn AsyncRead + Send + Unpin>)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(DomainError::Invariant(format!("mirror open: {e}"))),
            }
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

/// Object-store-backed mirror (S3/GCS/Azure/in-memory). Holds the same
/// `Arc<dyn ObjectStore>` the CAS [`ObjectStoreStorage`](super::object_store_backend)
/// uses; the logical `key` maps directly to an `object_store` path. Overwrite
/// is the object store's native put semantics (last write wins).
pub struct ObjectStoreMetadataMirror {
    store: Arc<dyn ObjectStore>,
}

impl ObjectStoreMetadataMirror {
    /// Construct an object-store mirror over `store`.
    pub fn new(store: Arc<dyn ObjectStore>) -> Self {
        Self { store }
    }

    /// Validate `key` for traversal, then map it to an object-store path.
    fn resolve(&self, key: &str) -> DomainResult<object_store::path::Path> {
        reject_traversal(key)?;
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
            let mut buf = Vec::new();
            tokio::io::copy(&mut body, &mut buf)
                .await
                .map_err(|e| DomainError::Invariant(format!("mirror read: {e}")))?;
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
        Box::pin(async move {
            let path = path?;
            match self.store.get(&path).await {
                Ok(result) => {
                    let byte_stream = result
                        .into_stream()
                        .map(|chunk| chunk.map_err(std::io::Error::other));
                    let reader = StreamReader::new(byte_stream);
                    Ok(Some(Box::new(reader) as Box<dyn AsyncRead + Send + Unpin>))
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
    use hort_domain::ports::metadata_mirror_store::MetadataMirrorStore;
    use tokio::io::AsyncReadExt;

    async fn read_all(mut r: Box<dyn AsyncRead + Send + Unpin>) -> Vec<u8> {
        let mut v = Vec::new();
        r.read_to_end(&mut v).await.unwrap();
        v
    }

    #[tokio::test]
    async fn fs_put_get_overwrite_delete_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = FilesystemMetadataMirror::new(dir.path().to_path_buf());

        // absent → None
        assert!(store.get("meta-mirror/npm/m/p").await.unwrap().is_none());

        // put → get
        store
            .put(
                "meta-mirror/npm/m/p",
                Box::new(std::io::Cursor::new(b"v1".to_vec())),
            )
            .await
            .unwrap();
        let got = store.get("meta-mirror/npm/m/p").await.unwrap().unwrap();
        assert_eq!(read_all(got).await, b"v1");

        // overwrite
        store
            .put(
                "meta-mirror/npm/m/p",
                Box::new(std::io::Cursor::new(b"v2-longer".to_vec())),
            )
            .await
            .unwrap();
        let got = store.get("meta-mirror/npm/m/p").await.unwrap().unwrap();
        assert_eq!(read_all(got).await, b"v2-longer");

        // delete → absent (and delete-absent is ok)
        store.delete("meta-mirror/npm/m/p").await.unwrap();
        assert!(store.get("meta-mirror/npm/m/p").await.unwrap().is_none());
        store.delete("meta-mirror/npm/m/p").await.unwrap();
    }

    /// F-44: mirror blobs hold authenticated-upstream metadata; they must
    /// be created mode 0600 (owner rw only), never the default 0644.
    #[cfg(unix)]
    #[tokio::test]
    async fn fs_put_creates_file_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let store = FilesystemMetadataMirror::new(dir.path().to_path_buf());
        store
            .put(
                "meta-mirror/npm/m/p",
                Box::new(std::io::Cursor::new(b"secret".to_vec())),
            )
            .await
            .unwrap();

        let path = dir.path().join("meta-mirror/npm/m/p");
        let meta = std::fs::metadata(&path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mirror blob must be mode 0o600, got {mode:o}");
    }

    /// Traversal defense-in-depth: the package segment is upstream-influenced
    /// (unlike CAS hash keys, which are regex-validated). A `..`-bearing key
    /// must be rejected with `DomainError::Validation`, not silently escape
    /// the mirror root.
    #[tokio::test]
    async fn fs_rejects_traversal_key() {
        use hort_domain::error::DomainError;

        let dir = tempfile::tempdir().unwrap();
        let store = FilesystemMetadataMirror::new(dir.path().to_path_buf());
        let bad = "meta-mirror/npm/m/../../../etc/passwd";

        // put
        let err = store
            .put(bad, Box::new(std::io::Cursor::new(b"x".to_vec())))
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)), "put: {err:?}");

        // get — `Ok` carries a non-Debug reader, so match rather than unwrap_err.
        match store.get(bad).await {
            Err(DomainError::Validation(_)) => {}
            other => panic!(
                "get: expected Validation Err, got Ok/other: {:?}",
                other.is_err()
            ),
        }

        // delete
        let err = store.delete(bad).await.unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)), "delete: {err:?}");
    }

    #[tokio::test]
    async fn object_store_put_get_overwrite_delete_roundtrip() {
        use object_store::memory::InMemory;
        use std::sync::Arc;

        let store = ObjectStoreMetadataMirror::new(Arc::new(InMemory::new()));

        // absent → None
        assert!(store.get("meta-mirror/npm/m/p").await.unwrap().is_none());

        // put → get
        store
            .put(
                "meta-mirror/npm/m/p",
                Box::new(std::io::Cursor::new(b"v1".to_vec())),
            )
            .await
            .unwrap();
        let got = store.get("meta-mirror/npm/m/p").await.unwrap().unwrap();
        assert_eq!(read_all(got).await, b"v1");

        // overwrite
        store
            .put(
                "meta-mirror/npm/m/p",
                Box::new(std::io::Cursor::new(b"v2-longer".to_vec())),
            )
            .await
            .unwrap();
        let got = store.get("meta-mirror/npm/m/p").await.unwrap().unwrap();
        assert_eq!(read_all(got).await, b"v2-longer");

        // delete → absent (and delete-absent is ok)
        store.delete("meta-mirror/npm/m/p").await.unwrap();
        assert!(store.get("meta-mirror/npm/m/p").await.unwrap().is_none());
        store.delete("meta-mirror/npm/m/p").await.unwrap();
    }

    /// Traversal defense applies to the object-store backend too — even
    /// though `object_store::path::Path` normalises, we reject up-front so
    /// the two backends share one validation contract.
    #[tokio::test]
    async fn object_store_rejects_traversal_key() {
        use hort_domain::error::DomainError;
        use object_store::memory::InMemory;
        use std::sync::Arc;

        let store = ObjectStoreMetadataMirror::new(Arc::new(InMemory::new()));
        let bad = "meta-mirror/npm/m/../escape";

        // get — match (non-Debug reader on Ok).
        match store.get(bad).await {
            Err(DomainError::Validation(_)) => {}
            other => panic!(
                "get: expected Validation Err, got Ok/other: {:?}",
                other.is_err()
            ),
        }
        // put + delete reject too.
        let err = store
            .put(bad, Box::new(std::io::Cursor::new(b"x".to_vec())))
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)), "put: {err:?}");
        let err = store.delete(bad).await.unwrap_err();
        assert!(matches!(err, DomainError::Validation(_)), "delete: {err:?}");
    }
}
