//! On-demand Maven checksum-sidecar generation (design §6, §11).
//!
//! A GET of `<file>.{sha1,sha256,sha512,md5}` returns the digest of the
//! **stored** `<file>`, never a client-uploaded copy (client sidecar PUTs
//! are accepted-and-discarded — [`crate::upload`]). Digests are computed
//! **on demand**, nothing is precomputed at ingest or persisted on the
//! artifact:
//!
//! - **`.sha256`** is the artifact's CAS [`ContentHash`] — the SHA-256
//!   already known from the `find_visible_by_path` row. No stream, no
//!   compute, no cache entry.
//! - **`.sha1` / `.sha512` / `.md5`** stream the stored blob from CAS
//!   through the requested hasher and hex-encode the digest. The hex is
//!   memoised in the **Evictable** `mavensum:{content_hash}:{algorithm}`
//!   keyspace ([`hort_app::ephemeral_keyspace`]) — the digest of immutable
//!   content is itself immutable, so the cache is purely recomputable
//!   (loss costs a re-hash, never correctness) and bounds a re-hash
//!   CPU-amplification vector. On a cache hit the blob is not re-read.
//!
//! The sidecar body is the bare lowercase hex (Maven sidecars are a bare
//! digest — no filename suffix), `Content-Type: text/plain`.
//!
//! ## Quarantine inheritance (§11)
//!
//! A sidecar GET resolves the **same target artifact** as the file GET
//! ([`ArtifactUseCase::find_visible_by_path`] on the base path) and
//! applies the **same status gate**: `Quarantined` → 503 + `Retry-After`;
//! `Rejected` / `ScanIndeterminate` → 403; only `Released` / `None` serve
//! the digest. A sidecar therefore reveals no more than the file's own
//! status response already does — it does **not** leak the digest (or mere
//! existence beyond the file's own 503) of a held version. The gate runs
//! *before* any CAS read or cache lookup, so a held artifact's digest is
//! never computed.

use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::Response;
use tokio::io::AsyncReadExt;

use hort_domain::entities::artifact::Artifact;
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::repository::Repository;

use hort_http_core::context::AppContext;
use hort_http_core::error::ApiError;

/// TTL for a memoised sidecar digest. The cached value is a recomputable
/// property of immutable content, so the TTL is a cache-hygiene bound
/// (cap memory growth from one-shot sidecar fetches), not a correctness
/// horizon — 24h is generous for the read-amplification a build's repeated
/// sidecar GETs cause, and the Evictable backend's LRU reclaims it under
/// pressure anyway.
const MAVENSUM_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Streaming read chunk size for the on-demand hash of a stored blob.
const HASH_READ_CHUNK: usize = 64 * 1024;

/// Serve an on-demand checksum sidecar for the stored file at
/// `base_path` (the request path with its `.{ext}` sidecar suffix already
/// stripped) using the algorithm token `algorithm`
/// (`"sha1"`/`"sha256"`/`"sha512"`/`"md5"`).
///
/// Resolves the SAME target artifact and applies the SAME status gate as
/// the file GET (`find_visible_by_path` → quarantine gate); a held target
/// returns the file's own non-servable response and the digest is never
/// computed. A missing target → 404 (same as a missing file).
pub(crate) async fn serve_sidecar(
    ctx: &Arc<AppContext>,
    repo: &Repository,
    base_path: &str,
    algorithm: &str,
    is_head: bool,
    actor: Option<&CallerPrincipal>,
) -> Result<Response, ApiError> {
    // Resolve the target file (same hop, same anti-enumeration 404 as the
    // file GET). A missing base file → 404 (a sidecar of nothing).
    let (_repo, artifact) = ctx
        .artifact_use_case
        .find_visible_by_path(&repo.key, base_path, actor)
        .await?;

    // Quarantine inheritance (§11): if the target is non-servable, return
    // the SAME response the file GET would — before any CAS read or cache
    // lookup, so a held digest is never computed or leaked.
    if let Some(blocked) = crate::non_servable_response(&artifact) {
        return Ok(blocked);
    }

    let hex = compute_or_cache_digest(ctx, &artifact, algorithm).await?;
    Ok(digest_response(hex, is_head))
}

/// Resolve the lowercase hex digest of `artifact` under `algorithm`,
/// short-circuiting `.sha256` to the CAS [`ContentHash`] (free) and
/// memoising `.sha1`/`.sha512`/`.md5` in the `mavensum:` keyspace.
async fn compute_or_cache_digest(
    ctx: &Arc<AppContext>,
    artifact: &Artifact,
    algorithm: &str,
) -> Result<String, ApiError> {
    let content_hash = artifact.sha256_checksum.as_ref();

    // `.sha256` is the CAS key itself — free, no stream, no cache entry.
    if algorithm == "sha256" {
        return Ok(content_hash.to_string());
    }

    // Cache lookup: the digest of immutable content under
    // `mavensum:{content_hash}:{algorithm}`.
    let cache_key = format!("mavensum:{content_hash}:{algorithm}");
    if let Some(bytes) = ctx
        .ephemeral_evictable
        .get(&cache_key)
        .await
        .map_err(|e| ApiError::from(hort_app::error::AppError::Domain(e)))?
    {
        if let Ok(hex) = std::str::from_utf8(&bytes) {
            // Cache hit — skip the re-hash (and the blob re-read).
            return Ok(hex.to_string());
        }
        // A non-utf8 cached value is corruption; fall through and recompute.
    }

    // Cache miss — stream the stored blob through the hasher.
    let hex = hash_blob(ctx, artifact, algorithm).await?;

    // Memoise (Evictable; best-effort). A write failure is non-fatal — the
    // digest is correct regardless; the next GET just re-hashes.
    let _ = ctx
        .ephemeral_evictable
        .put(
            &cache_key,
            Bytes::from(hex.clone().into_bytes()),
            MAVENSUM_TTL,
        )
        .await;

    Ok(hex)
}

/// The dynamic hasher trait re-exported by every RustCrypto hashing crate
/// (`sha1`/`sha2`/`md-5`) — a pure trait, NOT an adapter. Boxing the chosen
/// hasher as `dyn DynDigest` lets the streaming read loop and the in-memory
/// dispatch be written ONCE, branching only on the algorithm token when the
/// hasher is selected (not per read).
use sha2::digest::DynDigest;

/// The boxed hasher alias. The `+ Send` bound is load-bearing: the streaming
/// path holds the hasher across the CAS-`download`/`read` `.await` points, so
/// the enclosing future must be `Send` for the axum `Handler` bound. The
/// RustCrypto hashers are all `Send`.
type BoxedHasher = Box<dyn DynDigest + Send>;

/// Construct the boxed streaming hasher for a STORED-blob sidecar token
/// (`.sha1`/`.sha512`/`.md5`). `.sha256` never reaches here — it
/// short-circuits to the CAS [`ContentHash`] in [`compute_or_cache_digest`].
/// Returns `None` for any other token (a parser bug — the caller fails
/// closed).
fn streaming_hasher_for(algorithm: &str) -> Option<BoxedHasher> {
    match algorithm {
        "sha1" => Some(Box::<sha1::Sha1>::default()),
        "sha512" => Some(Box::<sha2::Sha512>::default()),
        "md5" => Some(Box::<md5::Md5>::default()),
        _ => None,
    }
}

/// Construct the boxed in-memory hasher for a metadata-sidecar token. Adds
/// `.sha256` to [`streaming_hasher_for`]'s set, because a generated
/// `maven-metadata.xml` document has no precomputed CAS hash — its `.sha256`
/// is hashed over the produced bytes like the others. Returns `None` for an
/// unknown token (fail-closed).
fn oneshot_hasher_for(algorithm: &str) -> Option<BoxedHasher> {
    match algorithm {
        "sha256" => Some(Box::<sha2::Sha256>::default()),
        other => streaming_hasher_for(other),
    }
}

/// Fail-closed error for an algorithm token no hasher handles. Same message
/// and shape (`Validation`, `maven.coordinate:` prefix → 400) for both the
/// streaming and in-memory dispatch — sha256 short-circuits / is handled
/// upstream, so any token reaching the `None` arm is a parser bug.
fn unsupported_algorithm(algorithm: &str) -> ApiError {
    ApiError::from(hort_app::error::AppError::Domain(
        hort_domain::error::DomainError::Validation(format!(
            "maven.coordinate: unsupported checksum algorithm {algorithm}"
        )),
    ))
}

/// Stream the stored blob for `artifact` from CAS through the `algorithm`
/// hasher and return the lowercase hex digest.
///
/// Reuses [`ArtifactUseCase::download`] for the CAS stream — the same path
/// the file GET uses. The caller has already applied the status gate, so
/// `download`'s own `is_downloadable()` re-check is satisfied for the
/// released/None artifact reaching here.
///
/// A single streaming read loop drives a `Box<dyn DynDigest>` chosen by
/// [`streaming_hasher_for`]; the per-algorithm branch is the hasher
/// selection only, so the read + error path is shared across `.sha1` /
/// `.sha512` / `.md5`.
async fn hash_blob(
    ctx: &Arc<AppContext>,
    artifact: &Artifact,
    algorithm: &str,
) -> Result<String, ApiError> {
    // The caller only dispatches the four `SIDECAR_EXTENSIONS`; sha256
    // short-circuits before reaching here. Any other token is a parser bug —
    // fail closed (before any CAS read) rather than serve a wrong digest.
    let mut hasher =
        streaming_hasher_for(algorithm).ok_or_else(|| unsupported_algorithm(algorithm))?;

    let (_artifact, mut stream) = ctx.artifact_use_case.download(artifact.id, None).await?;

    let mut buf = vec![0u8; HASH_READ_CHUNK];
    loop {
        let n = stream
            .read(&mut buf)
            .await
            .map_err(|e| ApiError::from(hort_app::error::AppError::Storage(e.to_string())))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Serve an on-demand checksum sidecar for a server-generated
/// `maven-metadata.xml` document, hashing the SAME bytes the metadata GET
/// produces (design §6). `maven-metadata.xml` is not a CAS artifact (it is
/// regenerated, filtered, per request), so its sidecar is **recomputed
/// fresh** rather than memoised — the document bytes are already produced
/// per request, so there is no immutable content hash to key a cache on and
/// no re-hash amplification to bound. `.sha256` over the produced bytes is
/// computed the same way as the others (there is no precomputed CAS hash
/// for a generated document).
pub(crate) fn serve_metadata_sidecar(
    xml_bytes: &[u8],
    algorithm: &str,
    is_head: bool,
) -> Result<Response, ApiError> {
    let hex = digest_bytes(xml_bytes, algorithm)?;
    Ok(digest_response(hex, is_head))
}

/// Lowercase hex digest of in-memory `bytes` under `algorithm`. Used for
/// the metadata-sidecar path (generated XML, recomputed fresh).
///
/// Shares the [`oneshot_hasher_for`] dispatch (which adds `.sha256` to the
/// stored-blob set, since a generated document has no precomputed CAS hash)
/// — the same fail-closed `None` arm as [`hash_blob`].
fn digest_bytes(bytes: &[u8], algorithm: &str) -> Result<String, ApiError> {
    let mut hasher =
        oneshot_hasher_for(algorithm).ok_or_else(|| unsupported_algorithm(algorithm))?;
    hasher.update(bytes);
    Ok(hex::encode(hasher.finalize()))
}

/// Build the `200 text/plain` sidecar response carrying the bare lowercase
/// hex digest (no filename suffix — Maven sidecars are a bare digest). On a
/// HEAD the status + headers are identical, body dropped.
fn digest_response(hex: String, is_head: bool) -> Response {
    let body = if is_head {
        Body::empty()
    } else {
        Body::from(hex)
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain")
        .body(body)
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Independent oracle: the lowercase hex digest of `bytes` under each
    /// algorithm, computed with the static RustCrypto APIs (NOT the dyn
    /// dispatch under test).
    fn oracle(bytes: &[u8], algorithm: &str) -> String {
        use md5::Md5;
        use sha1::Sha1;
        use sha2::{Digest, Sha256, Sha512};
        match algorithm {
            "sha1" => hex::encode(Sha1::digest(bytes)),
            "sha256" => hex::encode(Sha256::digest(bytes)),
            "sha512" => hex::encode(Sha512::digest(bytes)),
            "md5" => hex::encode(Md5::digest(bytes)),
            other => panic!("oracle has no algorithm {other}"),
        }
    }

    /// `digest_bytes` (the metadata-sidecar path) computes the correct hex
    /// for ALL four supported tokens — including `sha256`, which is unique to
    /// the in-memory dispatch (the stored-blob path short-circuits sha256 to
    /// the CAS hash). Pins the per-algorithm metadata-sidecar arms.
    #[test]
    fn digest_bytes_matches_oracle_for_every_supported_algorithm() {
        let bytes = b"maven-metadata-xml-bytes-\x00\x01\x02-payload";
        for algorithm in ["sha1", "sha256", "sha512", "md5"] {
            let got = digest_bytes(bytes, algorithm)
                .unwrap_or_else(|_| panic!("{algorithm} is a supported algorithm"));
            assert_eq!(
                got,
                oracle(bytes, algorithm),
                "{algorithm} digest_bytes must equal the static-API digest"
            );
        }
    }

    /// The empty-input edge: `digest_bytes` still produces each algorithm's
    /// well-known empty digest (the loop/update-with-nothing path).
    #[test]
    fn digest_bytes_handles_empty_input() {
        for algorithm in ["sha1", "sha256", "sha512", "md5"] {
            let got = digest_bytes(b"", algorithm)
                .unwrap_or_else(|_| panic!("{algorithm} hashes empty input"));
            assert_eq!(
                got,
                oracle(b"", algorithm),
                "{algorithm} of empty input matches the static-API digest"
            );
        }
    }

    /// An unknown token reaches the shared fail-closed `None` arm → a
    /// `Validation` error carrying the `maven.coordinate:` prefix. Pins the
    /// defensive arm of the in-memory dispatch (the parser never emits this
    /// token; it would be a bug). `ApiError` has no `Debug`, so assert on the
    /// wrapped `AppError`'s `Display`.
    #[test]
    fn digest_bytes_unknown_algorithm_is_validation_error() {
        let err = match digest_bytes(b"x", "bogus") {
            Err(e) => e,
            Ok(hex) => panic!("an unknown token must fail closed, got {hex}"),
        };
        assert!(
            matches!(
                err.0,
                hort_app::error::AppError::Domain(hort_domain::error::DomainError::Validation(_))
            ),
            "unknown token is a Domain Validation error"
        );
        let msg = err.0.to_string();
        assert!(
            msg.contains("maven.coordinate")
                && msg.contains("unsupported checksum algorithm")
                && msg.contains("bogus"),
            "fail-closed error carries the maven.coordinate prefix + token: {msg}"
        );
    }

    /// The dispatch boundary: `streaming_hasher_for` rejects `sha256` (it must
    /// short-circuit to the CAS hash, never stream) and every unknown token,
    /// while `oneshot_hasher_for` accepts `sha256`. Pins the one behavioural
    /// difference between the two shared selectors.
    #[test]
    fn streaming_dispatch_rejects_sha256_but_oneshot_accepts_it() {
        assert!(
            streaming_hasher_for("sha256").is_none(),
            "sha256 must never stream — it is the CAS hash"
        );
        assert!(
            oneshot_hasher_for("sha256").is_some(),
            "the metadata path hashes sha256 over the produced bytes"
        );
        for token in ["sha1", "sha512", "md5"] {
            assert!(streaming_hasher_for(token).is_some(), "{token} streams");
            assert!(oneshot_hasher_for(token).is_some(), "{token} one-shots");
        }
        assert!(streaming_hasher_for("bogus").is_none());
        assert!(oneshot_hasher_for("bogus").is_none());
    }
}
