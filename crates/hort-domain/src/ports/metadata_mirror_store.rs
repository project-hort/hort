//! Logical-keyed, streaming, overwrite blob store for the raw upstream
//! metadata mirror (ADR 0026).
//!
//! Distinct from the content-addressed [`StoragePort`](super::storage::StoragePort):
//! metadata is MUTABLE (overwritten when upstream publishes a new version),
//! so an immutable CAS would orphan-grow and collide with a future CAS
//! orphan-reaper. This port is logical-keyed + overwrite — less machinery
//! than CAS (no hashing, no refcount).

use tokio::io::AsyncRead;

use crate::error::DomainResult;
use crate::types::ContentHash;

use super::BoxFuture;

/// Build the mirror key for a package's raw metadata body.
///
/// `package` is passed pre-url-encoded by the caller (matching the existing
/// cache-key convention, e.g. `@types%2fnode`). Kept in a dedicated
/// `meta-mirror/` keyspace so it never collides with artifact CAS content.
pub fn mirror_key(format: &str, mapping_id: &str, package: &str) -> String {
    format!("meta-mirror/{format}/{mapping_id}/{package}")
}

/// Streaming, overwrite, logical-keyed blob store for raw upstream metadata.
pub trait MetadataMirrorStore: Send + Sync {
    /// Stream `body` to `key`, replacing any prior value (overwrite).
    /// `body_digest` is SHA-256 of the raw body, computed by the upstream
    /// fetch while it writes the cache tempfile. Implementations verify it
    /// before committing the in-band frame (ADR 0026); callers must supply
    /// the digest of exactly the bytes in `body`.
    fn put(
        &self,
        key: &str,
        body: Box<dyn AsyncRead + Send + Unpin>,
        body_digest: ContentHash,
    ) -> BoxFuture<'_, DomainResult<()>>;

    /// Stream the mirrored body back, or `Ok(None)` if absent.
    fn get(
        &self,
        key: &str,
    ) -> BoxFuture<'_, DomainResult<Option<Box<dyn AsyncRead + Send + Unpin>>>>;

    /// Remove the mirrored body (retention / GC). Absent key is `Ok(())`.
    fn delete(&self, key: &str) -> BoxFuture<'_, DomainResult<()>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mirror_key_is_format_scoped_and_url_encodes_package() {
        // Scoped npm names contain '/'; the package segment must be the
        // pre-encoded form the caller passes (callers already url-encode).
        let k = mirror_key(
            "npm",
            "11111111-1111-1111-1111-111111111111",
            "@types%2fnode",
        );
        assert_eq!(
            k,
            "meta-mirror/npm/11111111-1111-1111-1111-111111111111/@types%2fnode"
        );
    }

    #[test]
    fn trait_is_object_safe() {
        fn _assert(_: &dyn MetadataMirrorStore) {}
    }
}
