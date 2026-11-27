//! Logical-keyed, streaming, overwrite blob store for the raw upstream
//! metadata mirror (ADR 0026).
//!
//! Distinct from the content-addressed [`StoragePort`](super::storage::StoragePort):
//! metadata is MUTABLE (overwritten when upstream publishes a new version),
//! so an immutable CAS would orphan-grow and collide with a future CAS
//! orphan-reaper. This port is logical-keyed + overwrite — the *key* is an
//! argument rather than a function of the body, so there is none of CAS's
//! dedup or refcount machinery. Hashing is not what separates the two: a
//! mirror body carries its own SHA-256, recorded in-band ahead of the bytes
//! and verified on the write ([`require_supplied_digest`]) and again on the
//! read. What CAS has and this does not is a key *derived* from that digest.

use tokio::io::AsyncRead;

use crate::error::{DomainError, DomainResult};
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

/// Refuse a body whose bytes do not hash to the digest supplied with
/// them.
///
/// Every implementation of [`MetadataMirrorStore::put`] that serves its
/// accepted bytes back from `get` ends here: either the claim the body
/// arrived with is one the bytes support, or nothing is committed. The
/// production backends write the frame header from the supplied digest
/// before the first body byte and hash the body as it streams past, so
/// this is the last step of the write; an in-memory double hashes the
/// buffer it read and calls it with the same argument. `actual_hex` is
/// the lowercase-hex digest the write computed — a hex string rather
/// than a [`ContentHash`] because the streaming producers hold one from
/// an incremental hasher, and a parse that cannot fail has no business
/// on that path.
///
/// It lives here, beside the obligation [`MetadataMirrorStore::put`]
/// states, rather than once per implementor: a test double that
/// round-trips has to refuse what production refuses, and a rule each
/// implementor re-states in its own words is a rule one of them will
/// state half of.
///
/// The message carries both digests because the refusal has two
/// different causes an operator has to tell apart — a caller that hashed
/// one body and streamed another, or a body that changed underneath the
/// two passes — and neither is distinguishable from "they differ" alone.
/// It needs no log of its own: every caller already reports a failed
/// mirror put, and this is the error it reports.
pub fn require_supplied_digest(
    actual_hex: &str,
    supplied: &ContentHash,
    key: &str,
) -> DomainResult<()> {
    if actual_hex == supplied.as_ref() {
        return Ok(());
    }
    Err(DomainError::Invariant(format!(
        "metadata mirror body for {key} does not hash to the digest supplied with it: \
         the bytes written hash to {actual_hex}, the caller supplied {supplied}"
    )))
}

/// SHA-256 of a body that is **already whole in memory**, in the form
/// [`MetadataMirrorStore::put`] takes its `body_digest`.
///
/// This is for bytes a caller is already holding — a fixture's literal,
/// or the in-memory outcome shape `cache_handle_from_bytes` builds. It is
/// not an invitation to buffer a body in order to get a digest: the
/// upstream bodies reaching this port run to tens of MiB (ADR 0026), and
/// every streaming producer hashes incrementally as it writes and hands
/// its hex straight to [`require_supplied_digest`]. A `put` that
/// materialised a body to call this would reintroduce exactly the
/// per-refresh resident cost ADR 0026 was written to end.
pub fn body_digest(bytes: &[u8]) -> ContentHash {
    use sha2::{Digest, Sha256};

    hex::encode(Sha256::digest(bytes))
        .parse()
        .expect("SHA-256 is a valid content hash")
}

/// Streaming, overwrite, logical-keyed blob store for raw upstream metadata.
pub trait MetadataMirrorStore: Send + Sync {
    /// Stream `body` to `key`, replacing any prior value (overwrite).
    /// `body_digest` is SHA-256 of the raw body, computed by the upstream
    /// fetch while it writes the cache tempfile. Callers must supply the
    /// digest of exactly the bytes in `body`.
    ///
    /// An implementation that serves those bytes back from [`Self::get`]
    /// verifies the pair through [`require_supplied_digest`] before
    /// committing anything (ADR 0026) — the production backends ahead of
    /// the in-band frame they commit, an in-memory double ahead of its
    /// insert. Nothing is committed on a refusal, and a refused overwrite
    /// leaves the key's previous body readable: in production the staged
    /// file is never renamed and the multipart is never completed, so a
    /// double that cleared the key first would show a state no backend
    /// can reach.
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

    /// The hash of the empty body and of a known literal, checked against
    /// the published SHA-256 vectors rather than against a second call to
    /// the same function — the digest this produces is what a `put` is
    /// verified against, so "it agrees with itself" proves nothing.
    #[test]
    fn body_digest_is_the_sha256_of_the_bytes() {
        assert_eq!(
            body_digest(b"").as_ref(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            body_digest(b"abc").as_ref(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// The pair a producer actually supplies — the digest of exactly the
    /// bytes it streamed — is accepted.
    #[test]
    fn a_body_paired_with_its_own_digest_is_accepted() {
        let body = b"{\"dist-tags\":{\"latest\":\"1.0.0\"}}";
        let supplied = body_digest(body);
        require_supplied_digest(supplied.as_ref(), &supplied, "meta-mirror/npm/m/express")
            .expect("a body paired with its own digest must be accepted");
    }

    /// A mismatch is refused, and the message names the key plus BOTH
    /// digests — an operator telling "hashed one body, streamed another"
    /// apart from "the body changed between the passes" has only those
    /// two values to do it with.
    #[test]
    fn a_mismatched_pair_is_refused_and_names_both_digests() {
        let written = body_digest(b"the bytes that were written");
        let claimed = body_digest(b"the bytes the caller hashed");
        let key = "meta-mirror/npm/m/express";

        let err = require_supplied_digest(written.as_ref(), &claimed, key)
            .expect_err("a mis-stated digest must be refused");
        assert!(
            matches!(&err, DomainError::Invariant(_)),
            "the refusal must be an invariant breach; got: {err:?}"
        );
        // `Invariant` is `#[error("{0}")]`, so this is the message itself.
        let message = err.to_string();
        assert!(message.contains(key), "must name the key; got: {message}");
        assert!(
            message.contains(written.as_ref()) && message.contains(claimed.as_ref()),
            "must carry both digests; got: {message}"
        );
        assert!(
            message.contains("does not hash to"),
            "the adapters' tests match on this phrase; got: {message}"
        );
    }

    /// Length and case are the two ways a hex string can differ from a
    /// [`ContentHash`]'s canonical form without differing as a number.
    /// `ContentHash` admits only 64 lowercase hex characters, so an
    /// upper-case or truncated `actual_hex` is a producer that did not
    /// hash the way the port requires — refused, not normalised.
    #[test]
    fn a_non_canonical_actual_hex_is_refused() {
        let supplied = body_digest(b"abc");
        for actual in [
            supplied.as_ref().to_ascii_uppercase(),
            supplied.as_ref()[..63].to_string(),
        ] {
            assert!(
                require_supplied_digest(&actual, &supplied, "k").is_err(),
                "{actual} is not the canonical digest and must be refused"
            );
        }
    }
}
