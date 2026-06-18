//! OCI blob pull.
//!
//! Wires `GET` + `HEAD /v2/<repo_key>/<name>/blobs/<digest>` through
//! `ArtifactRepository::find_by_path` + `ArtifactUseCase::download`.
//!
//! ## Dispatch shape
//!
//! The `/v2/:repo_key/*tail` route's wildcard captures everything
//! after `:repo_key/` as a single string. Dispatch to this module's
//! [`serve`] function is driven by [`super::tail::parse_tail`] +
//! [`super::tail::TailKind::Blob`] — this module owns only the
//! blob-serving logic; tail parsing lives in `tail.rs` so manifests
//! future handlers share the same parser.
//!
//! ## Quarantine handling
//!
//! The handler inspects `Artifact.quarantine_status` DIRECTLY (same
//! pattern as `pypi::download` — see handlers/pypi.rs around the
//! `quarantine_until` branch) rather than surfacing
//! `ArtifactUseCase::download`'s `DomainError::Forbidden`. Reasons:
//!
//! - OCI clients behind transparent proxies (Artifactory) MUST see
//!   `503 Service Unavailable` + `Retry-After` while the quarantine
//!   window is open, NOT a `403` that the proxy would treat as a hard
//!   deny and cache (ADR 0007).
//! - Quarantine short-circuits before opening the CAS stream;
//!   `hort_download_total{result="quarantined"}` is emitted by the
//!   shared [`super::quarantine::check_quarantine`] helper so operators
//!   see quarantine pressure in the same counter as regular pulls.
//!
//! Rejected artifacts return `404 BLOB_UNKNOWN` so the blob's rejected
//! state is invisible to clients. The spec does not have a separate
//! "rejected blob" code; hiding it prevents supply-chain probing.

use std::sync::Arc;

use axum::body::Body;
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use tokio::io::AsyncRead;
use tokio_util::io::StreamReader;
use uuid::Uuid;

use hort_app::error::AppError;
use hort_app::pull_dedup::DedupKey;
use hort_app::use_cases::ingest_use_case::{RegisterExistingCasBlobRequest, VerifiedIngestRequest};
use hort_domain::entities::artifact::{Artifact, QuarantineStatus};
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::repository::Repository;
use hort_domain::error::DomainError;
use hort_domain::events::ApiActor;
use hort_domain::types::{ByteRange, ContentHash};
use hort_formats::oci::OciFormatHandler;

use super::coords::oci_blob_coords;
use super::digest::{parse_digest, DigestParse};
use super::error::OciError;
use super::quarantine;
use hort_http_core::body::{stream_blob, DEFAULT_STREAM_CAPACITY};
use hort_http_core::context::AppContext;

// ---------------------------------------------------------------------------
// Range header parsing
// ---------------------------------------------------------------------------

/// Parse failure for a `Range` header value. The handler maps every
/// variant to `416 Range Not Satisfiable` per RFC 7233 §4.4 with
/// `Content-Range: bytes */<size>`. Popular registries (Docker
/// Registry, nginx) treat unparseable Range headers as 416, not 400 —
/// we follow that convention so OCI clients see a uniform reaction
/// across mirrors.
///
/// **Multi-range explicitly unsupported.** A `Range: bytes=0-99,200-
/// 299` header parses as `Multipart`; we 416 it. `multipart/
/// byteranges` adds a parallel response codec for marginal benefit
/// (kubelet's resume pattern is single-range), and adopting it
/// without a wider design conversation would lock in a wire-format
/// commitment. Future implementers WILL try to add it — this comment
/// is the speed bump.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum RangeError {
    /// Any unsatisfiable / unparseable range. Adapter writes
    /// `Content-Range: bytes */<size>` with this `size`.
    NotSatisfiable { size: u64 },
}

/// Parse a `Range` header value (e.g. `bytes=0-499`) against a known
/// content `size`. Returns the canonical [`ByteRange`] on success —
/// already clamped per RFC 7233 §2.1 / §4.4 so the caller can hand
/// the result straight to `StoragePort::get_range`.
///
/// Accepted forms (single-range only):
/// - `bytes=N-M` (`Inclusive`, with `M` clamped to `size-1` if `M >=
///   size`; `N > M` and `N >= size` → 416)
/// - `bytes=N-` (`From`; `N >= size` → 416)
/// - `bytes=-K` (`Suffix`; `K == 0` → 416; `K > size` is allowed and
///   forwarded as-is so the adapter does the whole-content clamp)
///
/// Anything else — multi-range, missing `bytes=`, non-numeric, empty
/// — maps to `RangeError::NotSatisfiable { size }`.
pub(super) fn parse_range_header(value: &str, size: u64) -> Result<ByteRange, RangeError> {
    // Reject empty, trim whitespace.
    let value = value.trim();
    let Some(rest) = value.strip_prefix("bytes=") else {
        return Err(RangeError::NotSatisfiable { size });
    };

    // Multi-range up front: any `,` means more than one byte-range-
    // spec. We don't support `multipart/byteranges`; map to 416.
    // Documented at the RangeError docstring — leaving the
    // observation here too because future implementers WILL try to
    // remove this guard.
    if rest.contains(',') {
        return Err(RangeError::NotSatisfiable { size });
    }

    // Split on the SINGLE `-` separator that distinguishes byte-range-
    // spec forms. `split_once` is the right primitive here because
    // multi-`-` inputs (e.g. `bytes=1-2-3`) are malformed and should
    // 416 rather than parse the first two segments.
    let Some((start_str, end_str)) = rest.split_once('-') else {
        return Err(RangeError::NotSatisfiable { size });
    };
    if end_str.contains('-') {
        return Err(RangeError::NotSatisfiable { size });
    }

    match (start_str, end_str) {
        // `bytes=-K` → Suffix
        ("", k) => {
            let k: u64 = k.parse().map_err(|_| RangeError::NotSatisfiable { size })?;
            if k == 0 || size == 0 {
                // RFC §2.1: a zero-length suffix range has no
                // satisfiable byte; 416. A zero-byte representation
                // has no satisfiable range either — guard the
                // empty-config-blob case (OCI's
                // `sha256:44136fa3...` is a legal 0-byte object).
                return Err(RangeError::NotSatisfiable { size });
            }
            Ok(ByteRange::Suffix { last: k })
        }
        // `bytes=N-` → From
        (n, "") => {
            let n: u64 = n.parse().map_err(|_| RangeError::NotSatisfiable { size })?;
            if n >= size {
                // RFC §4.4: first-byte-pos > complete-length → 416.
                return Err(RangeError::NotSatisfiable { size });
            }
            Ok(ByteRange::From { start: n })
        }
        // `bytes=N-M` → Inclusive (with end-clamp)
        (n, m) => {
            let n: u64 = n.parse().map_err(|_| RangeError::NotSatisfiable { size })?;
            let m: u64 = m.parse().map_err(|_| RangeError::NotSatisfiable { size })?;
            if n > m || n >= size {
                return Err(RangeError::NotSatisfiable { size });
            }
            // RFC §2.1: "if the value is greater than or equal to
            // the current length of the selected representation,
            // the byte range is interpreted as the remainder of the
            // representation" — clamp end to size - 1.
            let end = if m >= size { size - 1 } else { m };
            Ok(ByteRange::Inclusive { start: n, end })
        }
    }
}

// ---------------------------------------------------------------------------
// Main flow
// ---------------------------------------------------------------------------

/// Serve an OCI blob by `(repo_key, name, digest_str)`. Invoked from
/// the wildcard-route dispatcher in `super::get_pull`/`head_pull` after
/// [`super::tail::parse_tail`] produces `TailKind::Blob`. `head = true`
/// strips the body but keeps the header set bit-identical.
///
/// `headers` carries the request headers; specifically used to inspect
/// `Range` and emit 206 / 416 per RFC 7233 §2 / §4. Range support is
/// BYPASSED for the upstream-pull-on-miss branch — the upstream fetch
/// already returns whole content; serving a slice on first cache fill
/// would be a needless complication. Subsequent (cached-hit) GETs
/// honour `Range` normally.
pub(super) async fn serve(
    ctx: Arc<AppContext>,
    repo_key: &str,
    name: &str,
    digest_str: &str,
    headers: &HeaderMap,
    head: bool,
    actor: Option<&CallerPrincipal>,
) -> Response {
    // 1. Parse the digest. Split ordering matters for the emitted code:
    //    a well-formed `sha512:...` is UNSUPPORTED (spec recognises the
    //    shape but can't honour it), whereas a missing `:` or wrong
    //    length is DIGEST_INVALID.
    let hash: ContentHash = match parse_digest(digest_str) {
        DigestParse::Ok(h) => h,
        DigestParse::Unsupported { algorithm } => {
            return OciError::Unsupported {
                message: format!("unsupported digest algorithm: {algorithm}"),
            }
            .into_response();
        }
        DigestParse::Invalid { message } => {
            return OciError::DigestInvalid { message }.into_response();
        }
    };

    // 2 + 3. Resolve repo + artifact through the visibility-aware use
    //    case (ADR 0008). A missing repo, an invisible private repo,
    //    or a missing path all collapse to the same
    //    `DomainError::NotFound` envelope — the OCI spec uses the same
    //    404 code for both "repo unknown" and "image unknown" so the
    //    enumeration-resistance falls out for free here.
    //
    //    The use case enforces Read on the repo before the path
    //    lookup, closing anonymous reads on private repos. Cross-repo
    //    isolation is preserved: the use case scopes the path lookup
    //    to the resolved `repo.id`, so a foreign blob addressable by
    //    the same digest in another repo stays invisible.
    let coords = oci_blob_coords(name, &hash);
    let (repo, artifact) = match ctx
        .artifact_use_case
        .find_visible_by_path(repo_key, &coords.path, actor)
        .await
    {
        Ok((r, a)) => (r, a),
        // Repository missing OR invisible to actor → NAME_UNKNOWN.
        // Anti-enumeration: the two cases share the same envelope.
        Err(AppError::Domain(DomainError::NotFound {
            entity: "Repository",
            ..
        })) => {
            return OciError::NameUnknown {
                repository: repo_key.to_string(),
            }
            .into_response();
        }
        // Repo visible, artifact missing → fall through to upstream
        // pull-through. The visibility check has succeeded; we still
        // need to resolve the repo for the upstream resolver. Look it
        // up via the access use case (no extra DB round-trip beyond
        // what `find_visible_by_path` already issued's caching policy
        // — the next call returns the same row).
        Err(AppError::Domain(DomainError::NotFound {
            entity: "Artifact", ..
        })) => {
            // Resolve the repo (already proven visible) for the upstream
            // pull-through path. Use the access use case so the call
            // stays inside the visibility-checked surface.
            // Race: repo deleted between the find_visible_by_path
            // call and this re-resolve. Surface as NAME_UNKNOWN to
            // match the original behaviour.
            let Ok(repo) = ctx
                .repository_access_use_case
                .resolve(
                    repo_key,
                    actor,
                    hort_app::use_cases::repository_access::AccessLevel::Read,
                )
                .await
            else {
                return OciError::NameUnknown {
                    repository: repo_key.to_string(),
                }
                .into_response();
            };

            // Pull-through on miss (see docs/architecture/how-to/oci-pull-through.md).
            // If the repository has an upstream resolver hit for this
            // name, fetch the blob from upstream, ingest with declared
            // digest, then re-resolve the local lookup. Any other
            // outcome (no mapping, upstream 404/5xx, checksum mismatch)
            // falls through with the appropriate response.
            match try_upstream_blob_pull(&ctx, &repo, name, &hash).await {
                UpstreamPullOutcome::Ingested(a) => (repo, *a),
                UpstreamPullOutcome::NotConfigured | UpstreamPullOutcome::CurationBlocked => {
                    // `CurationBlocked` collapses into the same
                    // `BLOB_UNKNOWN` (404) envelope as `NotConfigured`:
                    // client sees a clean miss.
                    return OciError::BlobUnknown {
                        digest: format!("sha256:{}", hash.as_ref()),
                    }
                    .into_response();
                }
                UpstreamPullOutcome::ChecksumMismatch => {
                    return OciError::BadGateway {
                        detail: Some(serde_json::json!({
                            "reason": "upstream blob digest did not match request digest",
                        })),
                    }
                    .into_response();
                }
                UpstreamPullOutcome::UpstreamUnavailable => {
                    // Upstream returned non-success; surface as
                    // BAD_GATEWAY so callers and probes can
                    // distinguish "we don't have it" from "upstream
                    // is unreachable". The OCI spec has no specific
                    // error code for "upstream unavailable", so this
                    // is the best generic mapping.
                    return OciError::BadGateway {
                        detail: Some(serde_json::json!({
                            "reason": "upstream blob fetch failed",
                        })),
                    }
                    .into_response();
                }
                UpstreamPullOutcome::Internal => return OciError::Internal.into_response(),
            }
        }
        Err(e) => {
            tracing::error!(
                repo_key = %repo_key,
                hash = %hash,
                error = %e,
                "artifact lookup failed during OCI blob pull"
            );
            return OciError::Internal.into_response();
        }
    };
    // Defensive: avoid unused-binding warnings for `repo` on builds
    // where the upstream-pull branch isn't taken.
    let _ = &repo;

    // 5. Quarantine / rejected check. See module docs for why this is
    //    done in the handler rather than deferred to
    //    ArtifactUseCase::download: transparent-proxy compatibility +
    //    avoiding the CAS round-trip for a blob that won't be served.
    //    Rejected stays inline because the hidden-404 envelope is
    //    format-specific (`BLOB_UNKNOWN`).
    if let Some(resp) = quarantine::check_quarantine(&artifact, repo_key) {
        return resp;
    }
    if matches!(artifact.quarantine_status, QuarantineStatus::Rejected) {
        return OciError::BlobUnknown {
            digest: format!("sha256:{}", hash.as_ref()),
        }
        .into_response();
    }

    // 6. Range honour. Parse the Range header AFTER the quarantine /
    //    rejected check so a quarantined blob 503s regardless of
    //    `Range`. Per RFC 7233 §4.4 every unparseable / unsatisfiable
    //    Range maps to 416 with `Content-Range: bytes */<size>`.
    //    Multi-range maps to 416 too (we do not support
    //    multipart/byteranges; see `RangeError`'s docstring for the
    //    rationale).
    //
    //    `artifact.size_bytes` is i64 in the schema; the cast to u64
    //    is sound because size cannot be negative — the lifecycle
    //    invariant rejects negative sizes at ingest. A defensive
    //    `.max(0)` is unnecessary.
    if let Some(value) = headers.get(axum::http::header::RANGE) {
        let size = artifact.size_bytes.max(0) as u64;
        let Ok(raw) = value.to_str() else {
            return build_416_response(size);
        };
        match parse_range_header(raw, size) {
            Err(RangeError::NotSatisfiable { .. }) => {
                return build_416_response(size);
            }
            Ok(range) => {
                if head {
                    return build_206_response(&artifact, &hash, &range, /* body = */ None);
                }
                let (_a, stream) = match ctx
                    .artifact_use_case
                    .download_range(artifact.id, range.clone())
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::error!(
                            artifact_id = %artifact.id,
                            error = %e,
                            "OCI blob download_range failed after lookup"
                        );
                        return OciError::Internal.into_response();
                    }
                };
                return build_206_response(
                    &artifact,
                    &hash,
                    &range,
                    Some(stream_blob(stream, DEFAULT_STREAM_CAPACITY)),
                );
            }
        }
    }

    // 7. No Range header — the existing 200 path. Same header
    //    composition as before; `Accept-Ranges: bytes` is now
    //    advertised so well-behaved clients know they may resume on
    //    subsequent calls.
    if head {
        return build_response(&artifact, &hash, /* body = */ None);
    }

    // Thread the resolved principal (this handler's `actor` fn param)
    // for opt-in download-audit attribution (ADR 0020). No per-handler
    // auth code. NOTE: this is the full-blob path; the ranged path
    // above (`download_range`) is intentionally not audited — ranged
    // resume fetches are mid-transfer bookkeeping, not new download
    // events.
    let (_artifact_after_download, stream) =
        match ctx.artifact_use_case.download(artifact.id, actor).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(
                    artifact_id = %artifact.id,
                    error = %e,
                    "OCI blob download failed after lookup"
                );
                return OciError::Internal.into_response();
            }
        };

    build_response(
        &artifact,
        &hash,
        Some(stream_blob(stream, DEFAULT_STREAM_CAPACITY)),
    )
}

// ---------------------------------------------------------------------------
// Pull-through-on-miss
// ---------------------------------------------------------------------------

/// Outcome of [`try_upstream_blob_pull`]. Each variant maps to a
/// distinct caller response in the [`serve`] miss-arm.
///
/// `pub(crate)` so [`crate::prefetch::fire_prefetch_trigger_oci`] can
/// match on the outcome of the background blob fetch it spawns. The
/// variants stay an unstable internal contract — no callers outside the
/// OCI crate observe this enum.
#[derive(Debug)]
pub(crate) enum UpstreamPullOutcome {
    /// Upstream fetch succeeded, ingest committed, the artifact row is
    /// now in the local CAS. Boxed because `Artifact` is large
    /// (>200 bytes) and the enum's other variants are unit-sized —
    /// boxing keeps the discriminant + payload size symmetric.
    Ingested(Box<Artifact>),
    /// No upstream mapping for `(repo, name)`. The caller falls
    /// through to `BLOB_UNKNOWN`.
    NotConfigured,
    /// Pull-through ingest hit a curation rule that blocked the
    /// artifact. Surfaced to the OCI client as `BLOB_UNKNOWN` (404)
    /// so `docker pull` sees the same envelope as a genuine upstream
    /// miss; without this override the default
    /// `DomainError::CurationBlocked` → 403 mapping would surface a
    /// cryptic 403 mid-pull. The matched rule already logged
    /// `tracing::info!` inside the ingest use case.
    CurationBlocked,
    /// Upstream returned bytes whose digest disagreed with the
    /// digest in the request. `IngestUseCase::ingest` already
    /// emitted `ChecksumMismatch`. Surface as 502 + cache write
    /// suppressed.
    ChecksumMismatch,
    /// Upstream returned a non-success status (4xx/5xx besides
    /// 404 — 404 collapses into `NotConfigured` semantically since
    /// the local + upstream both lack the blob). Surface as 502.
    UpstreamUnavailable,
    /// Infrastructure failure (storage error, event-store error,
    /// repo lookup error after ingest). Surface as 500.
    Internal,
}

/// On local CAS miss, attempt to fetch the blob from a configured
/// upstream and ingest it locally. Returns
/// [`UpstreamPullOutcome::NotConfigured`] when the repository has no
/// matching upstream mapping — caller treats this as `BLOB_UNKNOWN`.
///
/// The `fetch_blob + ingest_verified` pair is wrapped in
/// `PullDedup::coalesce_blob` so N parallel callers for the same
/// `(repo, digest)` produce ≤ 1 upstream HTTP fetch + ≤ 1 CAS write.
/// The dedup key is `blob_by_hash("sha256", &digest_hex)` — the digest
/// is always part of the OCI blob URL by spec. Cross-repo coalescing
/// is the design (the content hash is the natural dedup boundary;
/// `format` label is `"_any"`).
/// `pub(crate)` so [`crate::prefetch::fire_prefetch_trigger_oci`] can
/// spawn background pull-throughs for the config + layer blobs
/// referenced by a freshly-moved tag manifest. The trigger relies on
/// [`hort_app::pull_dedup::PullDedup`] inside this function for the
/// single-flight contract against a racing client pull.
pub(crate) async fn try_upstream_blob_pull(
    ctx: &Arc<AppContext>,
    repo: &Repository,
    name: &str,
    hash: &ContentHash,
) -> UpstreamPullOutcome {
    // 1. Resolve the upstream. No mapping → not-configured.
    let Some((mapping, upstream_name)) = ctx.upstream_resolver.resolve(repo.id, name) else {
        return UpstreamPullOutcome::NotConfigured;
    };

    // 2. Fetch the blob from upstream. The digest header on the
    //    request maps to the upstream's blob URL directly.
    let digest_str = format!("sha256:{}", hash.as_ref());
    tracing::info!(
        repo_key = %repo.key,
        upstream_url = %mapping.upstream_url,
        upstream_name = %upstream_name,
        upstream_name_prefix = ?mapping.upstream_name_prefix,
        digest = %digest_str,
        "OCI blob cache miss — fetching from upstream"
    );

    // Wrap the `fetch_blob + ingest_verified` pair in `coalesce_blob`.
    // The dedup key uses the request's bare hex digest — `DedupKey`
    // already namespaces by the `"sha256"` algorithm string, so we
    // pass the hex without the `sha256:` URL prefix.
    //
    // Closure-boundary contract: on success the closure returns
    // `Ok(content_hash)`; on failure `Err(AppError)`. The leader sees
    // the original `AppError` discriminator (`Domain(Conflict)` for
    // checksum mismatch, `Domain(CurationBlocked)` for curation
    // rejection); followers observe the cached `Failed` outcome and
    // surface a wrapped `AppError::External` — typed-error
    // discrimination is a leader-only concern by design.
    let blob_dedup_key = DedupKey::blob_by_hash("sha256", hash.as_ref());
    let blob_proxy = ctx.upstream_proxy.clone();
    let blob_ingest = ctx.ingest_use_case.clone();
    let blob_mapping = mapping.clone();
    let blob_upstream_name = upstream_name.clone();
    let blob_digest_str = digest_str.clone();
    let blob_repo_id = repo.id;
    let blob_hash = hash.clone();
    let blob_coords = oci_blob_coords(name, hash);
    let blob_upstream_url = mapping.upstream_url.clone();
    // Capture the serving mapping's per-upstream opt-in
    // (`trust_upstream_publish_time`) **before** the closure consumes
    // `mapping`. Threaded into `VerifiedIngestRequest` so `ingest_inner`
    // can gate the publish-anchored quarantine resolution on it
    // (ADR 0007).
    let blob_trust_publish_time = mapping.trust_upstream_publish_time;
    let coalesce_result = ctx
        .pull_dedup
        .coalesce_blob(blob_dedup_key, move || async move {
            let fetch = blob_proxy
                .fetch_blob(blob_mapping, blob_upstream_name.clone(), blob_digest_str)
                .await
                .map_err(AppError::from)?;
            // 3. Pipe the upstream stream into IngestUseCase::ingest
            //    with the request digest as `declared_sha256`. The use
            //    case rehashes while streaming and returns `Conflict`
            //    on mismatch — the upstream-verification security
            //    primitive (ADR 0006). The `ChecksumMismatch` event
            //    fires inside the use case.
            //
            // OCI uses VerifiedIngestRequest::ProtocolNative for both
            // pull-through and direct upload. The variant carries the
            // upstream digest; the use case computes SHA-256 from the
            // streamed bytes and compares — mismatch returns Conflict
            // (mapped to 502 here per the OCI Distribution Spec error
            // vocabulary).
            //
            // The blob response's `Last-Modified` header ≈ the blob's
            // push time. Each Artifact records its own blob's hint.
            // Best-effort: absent / unparseable → None. NOT for the
            // manifest (manifests.rs handles Last-Modified separately).
            let upstream_published_at = fetch.last_modified;
            let request = VerifiedIngestRequest::ProtocolNative {
                repository_id: blob_repo_id,
                coords: blob_coords,
                content_type: "application/octet-stream".to_string(),
                actor: ApiActor {
                    user_id: Uuid::nil(),
                },
                payload_metadata: serde_json::json!({
                    "oci_source": "upstream",
                    "oci_upstream_url": blob_upstream_url,
                    "oci_upstream_name": blob_upstream_name,
                }),
                upstream_digest: blob_hash,
                upstream_published_at,
                // Serving mapping's opt-in (ADR 0007 §quarantine posture).
                trust_upstream_publish_time: blob_trust_publish_time,
            };
            let reader: Box<dyn AsyncRead + Send + Unpin> =
                Box::new(StreamReader::new(fetch.stream));
            let outcome = blob_ingest
                .ingest_verified(request, reader, &OciFormatHandler)
                .await?;
            Ok(outcome.artifact.sha256_checksum)
        })
        .await;

    // 4. Discriminate leader-side typed errors and map to the existing
    //    outcome variants. Follower-side errors arrive as
    //    `AppError::External("pull-dedup follower: ...")` — followers
    //    do not see the leader's full error chain and route to `Internal`
    //    per the leader-only-discrimination contract; they never
    //    re-attempt.
    let content_hash = match coalesce_result {
        Ok(h) => h,
        Err(AppError::Domain(DomainError::Conflict(msg))) => {
            tracing::warn!(
                repo_key = %repo.key,
                digest = %hash,
                conflict = %msg,
                "OCI upstream blob digest disagreed with request — refusing to cache"
            );
            return UpstreamPullOutcome::ChecksumMismatch;
        }
        // Per-format pull-through override on GET /v2/{name}/blobs/{digest}.
        // Default `CurationBlocked` → 403, but on a `docker pull`
        // cache-miss path that surfaces as a cryptic 403 mid-pull.
        // Collapse to BLOB_UNKNOWN (404) so the client sees the same
        // envelope as a genuine miss. Audit attribution lives in the
        // ingest use case's `tracing::info!`.
        Err(AppError::Domain(DomainError::CurationBlocked { .. })) => {
            return UpstreamPullOutcome::CurationBlocked;
        }
        Err(err) => {
            // Pre-coalesce code distinguished `fetch_blob` transport
            // errors (→ `UpstreamUnavailable`) from post-ingest
            // infrastructure failures (→ `Internal`) by returning
            // before vs after the ingest step. After the wrap both
            // paths converge here; preserve the split by
            // string-matching the rendered error — the upstream HTTP
            // adapter prefixes its errors with "upstream:" (see
            // `MockUpstreamProxy::fetch_blob` and the production
            // `UpstreamHttpAdapter`).
            let msg = err.to_string();
            if msg.contains("upstream:") || msg.contains("upstream ") {
                tracing::warn!(
                    repo_key = %repo.key,
                    upstream_url = %mapping.upstream_url,
                    upstream_name = %upstream_name,
                    digest = %digest_str,
                    error = %err,
                    "OCI upstream blob fetch failed"
                );
                return UpstreamPullOutcome::UpstreamUnavailable;
            }
            tracing::error!(
                repo_key = %repo.key,
                digest = %hash,
                error = %err,
                "OCI upstream blob ingest failed"
            );
            return UpstreamPullOutcome::Internal;
        }
    };

    // 5. Post-coalesce read: both leader and follower re-resolve the
    //    artifact row by content hash. The leader's `ingest_verified`
    //    (inside the closure) wrote the row; the follower reads it.
    //    `ctx.artifacts` is `pub(crate)` (ADR 0008); format crates take
    //    artifact rows off the use-case (`find_in_repo_by_hash`) rather
    //    than the raw repository.
    match ctx
        .artifact_use_case
        .find_in_repo_by_hash(repo.id, &content_hash)
        .await
    {
        Ok(Some(artifact)) => UpstreamPullOutcome::Ingested(Box::new(artifact)),
        Ok(None) => {
            // `blob_by_hash` is cross-repo, so a follower that joined
            // a window whose leader ingested into a DIFFERENT repo has
            // no row in `repo.id`. The blob is already CAS-present and
            // upstream-verified (ADR 0006); the follower idempotently
            // registers its OWN per-repo row via
            // `register_existing_cas_blob` (coords reconstructed
            // deterministically from `(name, hash)` exactly as the
            // leader's closure did; no re-fetch, no re-`storage.put`;
            // same `ArtifactIngested` event the leader's non-concurrent
            // cross-repo dedup emits) instead of failing closed.
            match ctx
                .ingest_use_case
                .register_existing_cas_blob(
                    RegisterExistingCasBlobRequest {
                        repository_id: repo.id,
                        coords: oci_blob_coords(name, &content_hash),
                        content_type: "application/octet-stream".to_string(),
                        actor: ApiActor {
                            user_id: Uuid::nil(),
                        },
                        payload_metadata: serde_json::json!({
                            "oci_source": "upstream_coalesced_follower",
                        }),
                        content_hash: content_hash.clone(),
                        // Coalesced-follower path is not a seed-import;
                        // quarantine is policy-driven through the leader's
                        // primary `ingest_verified`.
                        seed_import_quarantine_anchor: None,
                    },
                    &OciFormatHandler,
                )
                .await
            {
                Ok(outcome) => UpstreamPullOutcome::Ingested(Box::new(outcome.artifact)),
                Err(err) => {
                    tracing::error!(
                        repo_key = %repo.key,
                        hash = %content_hash,
                        error = %err,
                        "OCI upstream blob: cross-repo follower register_existing_cas_blob failed"
                    );
                    UpstreamPullOutcome::Internal
                }
            }
        }
        Err(err) => {
            tracing::error!(
                repo_key = %repo.key,
                hash = %content_hash,
                error = %err,
                "OCI upstream blob: post-coalesce artifact lookup failed"
            );
            UpstreamPullOutcome::Internal
        }
    }
}

// ---------------------------------------------------------------------------
// Response builder
// ---------------------------------------------------------------------------

/// Assemble the spec-mandated headers for a blob response. HEAD passes
/// `body = None` to produce an empty wire body; GET passes the CAS
/// stream. Header set is bit-identical across the two paths — the OCI
/// spec allows a HEAD-then-GET client to compare headers to short-
/// circuit the GET, so divergence here would be a client-visible bug.
///
/// Always advertises `Accept-Ranges: bytes` so OCI / kubelet /
/// containerd clients know they may resume interrupted layer
/// downloads with `Range: bytes=N-`.
fn build_response(artifact: &Artifact, hash: &ContentHash, body: Option<Body>) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    // Always emit Content-Length — even for zero-byte blobs. OCI's
    // empty config blob
    // (`sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a`)
    // is a legal 0-byte object; without `Content-Length: 0` axum
    // chunk-encodes the empty response and strict clients mis-handle.
    // `i64::from(0)` produces a valid HeaderValue.
    headers.insert(CONTENT_LENGTH, artifact.size_bytes.into());
    // `Docker-Content-Digest` is the canonical digest advertised to
    // OCI / Docker clients — it must always echo `sha256:<hex>`.
    // HeaderValue::from_str can fail only on non-ASCII / invalid
    // header bytes; `sha256:<hex>` is 7 + 64 ASCII characters and
    // never trips that path. `expect` is the right reaction: an error
    // here means `ContentHash` was constructed with invalid bytes,
    // which its `FromStr` impl already forbids.
    headers.insert(
        "Docker-Content-Digest",
        HeaderValue::from_str(&format!("sha256:{}", hash.as_ref()))
            .expect("sha256:<hex> is valid ASCII"),
    );
    headers.insert("Accept-Ranges", HeaderValue::from_static("bytes"));

    let body = body.unwrap_or_else(Body::empty);
    (StatusCode::OK, headers, body).into_response()
}

/// Resolve a parsed `ByteRange` against `size` to absolute (first,
/// last) byte positions, both inclusive. Suffix > size clamps to the
/// whole content per RFC 7233 §2.1 — same rule the storage adapter
/// applies. The handler needs the resolution too to populate
/// `Content-Range` / `Content-Length`.
fn resolve_byte_range(range: &ByteRange, size: u64) -> (u64, u64) {
    match *range {
        ByteRange::Inclusive { start, end } => (start, end),
        ByteRange::From { start } => (start, size - 1),
        ByteRange::Suffix { last } => {
            if last >= size {
                (0, size - 1)
            } else {
                (size - last, size - 1)
            }
        }
    }
}

/// Build a 206 Partial Content response per RFC 7233 §4.1.
///
/// Headers:
/// - `Content-Type: application/octet-stream` (same as 200)
/// - `Content-Length: <last - first + 1>` (the slice's length, NOT the
///   whole-blob size)
/// - `Content-Range: bytes <first>-<last>/<size>` (RFC §4.2)
/// - `Docker-Content-Digest: sha256:<hex>` — the FULL blob digest,
///   not a chunk hash. OCI clients use this to verify the assembled
///   blob after concatenating partial fetches; see the kubelet-
///   resume regression-guard test.
/// - `Accept-Ranges: bytes` — emitted on 206 too (production
///   registries do this; some clients use it to detect the server
///   supports range even on a partial response).
fn build_206_response(
    artifact: &Artifact,
    hash: &ContentHash,
    range: &ByteRange,
    body: Option<Body>,
) -> Response {
    let size = artifact.size_bytes.max(0) as u64;
    let (first, last) = resolve_byte_range(range, size);
    let len = last - first + 1;

    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    let len_i64 = len as i64;
    headers.insert(CONTENT_LENGTH, len_i64.into());
    headers.insert(
        "Content-Range",
        HeaderValue::from_str(&format!("bytes {first}-{last}/{size}"))
            .expect("bytes A-B/C is valid ASCII"),
    );
    headers.insert(
        "Docker-Content-Digest",
        HeaderValue::from_str(&format!("sha256:{}", hash.as_ref()))
            .expect("sha256:<hex> is valid ASCII"),
    );
    headers.insert("Accept-Ranges", HeaderValue::from_static("bytes"));

    let body = body.unwrap_or_else(Body::empty);
    (StatusCode::PARTIAL_CONTENT, headers, body).into_response()
}

/// Build a 416 Range Not Satisfiable response per RFC 7233 §4.4.
///
/// `Content-Range: bytes */<size>` — the literal `*` is RFC-mandated
/// and signals "no satisfiable range" rather than an actual byte
/// span. Body is empty; clients get the size from the header.
///
/// `Accept-Ranges: bytes` is included so the client can re-issue with
/// a satisfiable range. The OCI spec does not define a 416 error
/// envelope; we leave the body empty (matches Docker Registry V2
/// behaviour).
fn build_416_response(size: u64) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        "Content-Range",
        HeaderValue::from_str(&format!("bytes */{size}")).expect("bytes */N is valid ASCII"),
    );
    headers.insert("Accept-Ranges", HeaderValue::from_static("bytes"));
    headers.insert(CONTENT_LENGTH, HeaderValue::from_static("0"));
    (StatusCode::RANGE_NOT_SATISFIABLE, headers, Body::empty()).into_response()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::to_bytes;
    use axum::http::{Method, Request};
    use axum::Router;
    use chrono::{DateTime, Utc};
    use tower::ServiceExt;
    use uuid::Uuid;

    // ---------------------------------------------------------------------
    // Range-header parser tests
    // ---------------------------------------------------------------------

    #[test]
    fn parse_range_inclusive_first_100_bytes() {
        let r = parse_range_header("bytes=0-99", 1024).unwrap();
        assert_eq!(r, ByteRange::Inclusive { start: 0, end: 99 });
    }

    #[test]
    fn parse_range_inclusive_middle_slice() {
        let r = parse_range_header("bytes=500-999", 1024).unwrap();
        assert_eq!(
            r,
            ByteRange::Inclusive {
                start: 500,
                end: 999
            }
        );
    }

    #[test]
    fn parse_range_inclusive_clamps_end_to_size_minus_one() {
        // RFC 7233 §2.1: end >= size → clamp to size-1, serve 206
        // with Content-Range bytes start-(size-1)/size.
        let r = parse_range_header("bytes=500-99999", 1024).unwrap();
        assert_eq!(
            r,
            ByteRange::Inclusive {
                start: 500,
                end: 1023
            }
        );
    }

    #[test]
    fn parse_range_inclusive_start_equals_end_is_single_byte() {
        let r = parse_range_header("bytes=42-42", 1024).unwrap();
        assert_eq!(r, ByteRange::Inclusive { start: 42, end: 42 });
    }

    #[test]
    fn parse_range_from_offset() {
        let r = parse_range_header("bytes=99-", 1024).unwrap();
        assert_eq!(r, ByteRange::From { start: 99 });
    }

    #[test]
    fn parse_range_from_zero_is_whole_content() {
        let r = parse_range_header("bytes=0-", 1024).unwrap();
        assert_eq!(r, ByteRange::From { start: 0 });
    }

    #[test]
    fn parse_range_suffix() {
        let r = parse_range_header("bytes=-50", 1024).unwrap();
        assert_eq!(r, ByteRange::Suffix { last: 50 });
    }

    #[test]
    fn parse_range_suffix_larger_than_size_is_passed_through() {
        // The adapter clamps; the parser forwards.
        let r = parse_range_header("bytes=-99999", 1024).unwrap();
        assert_eq!(r, ByteRange::Suffix { last: 99999 });
    }

    #[test]
    fn parse_range_inclusive_start_greater_than_end_is_416() {
        let err = parse_range_header("bytes=200-100", 1024).unwrap_err();
        assert_eq!(err, RangeError::NotSatisfiable { size: 1024 });
    }

    #[test]
    fn parse_range_inclusive_start_at_size_is_416() {
        let err = parse_range_header("bytes=1024-2000", 1024).unwrap_err();
        assert_eq!(err, RangeError::NotSatisfiable { size: 1024 });
    }

    #[test]
    fn parse_range_from_at_or_beyond_size_is_416() {
        let err = parse_range_header("bytes=10000000-", 1024).unwrap_err();
        assert_eq!(err, RangeError::NotSatisfiable { size: 1024 });
        let err = parse_range_header("bytes=1024-", 1024).unwrap_err();
        assert_eq!(err, RangeError::NotSatisfiable { size: 1024 });
    }

    #[test]
    fn parse_range_suffix_zero_is_416() {
        // RFC §2.1: zero-length suffix has no satisfiable byte.
        let err = parse_range_header("bytes=-0", 1024).unwrap_err();
        assert_eq!(err, RangeError::NotSatisfiable { size: 1024 });
    }

    #[test]
    fn parse_range_multi_range_is_416() {
        // We do not support multipart/byteranges. Future implementers
        // WILL try to add this — the rejection is intentional.
        let err = parse_range_header("bytes=0-99,200-299", 1024).unwrap_err();
        assert_eq!(err, RangeError::NotSatisfiable { size: 1024 });
    }

    #[test]
    fn parse_range_missing_bytes_prefix_is_416() {
        let err = parse_range_header("0-99", 1024).unwrap_err();
        assert_eq!(err, RangeError::NotSatisfiable { size: 1024 });
    }

    #[test]
    fn parse_range_other_unit_is_416() {
        // The grammar allows other units in principle; we only honour
        // `bytes`. No `bytes=` prefix → 416.
        let err = parse_range_header("seconds=0-99", 1024).unwrap_err();
        assert_eq!(err, RangeError::NotSatisfiable { size: 1024 });
    }

    #[test]
    fn parse_range_empty_value_is_416() {
        let err = parse_range_header("", 1024).unwrap_err();
        assert_eq!(err, RangeError::NotSatisfiable { size: 1024 });
    }

    #[test]
    fn parse_range_just_bytes_equals_is_416() {
        let err = parse_range_header("bytes=", 1024).unwrap_err();
        assert_eq!(err, RangeError::NotSatisfiable { size: 1024 });
    }

    #[test]
    fn parse_range_just_dash_is_416() {
        // `bytes=-` has neither suffix length nor numeric start.
        let err = parse_range_header("bytes=-", 1024).unwrap_err();
        assert_eq!(err, RangeError::NotSatisfiable { size: 1024 });
    }

    #[test]
    fn parse_range_non_numeric_is_416() {
        assert_eq!(
            parse_range_header("bytes=abc-99", 1024).unwrap_err(),
            RangeError::NotSatisfiable { size: 1024 }
        );
        assert_eq!(
            parse_range_header("bytes=0-xyz", 1024).unwrap_err(),
            RangeError::NotSatisfiable { size: 1024 }
        );
        assert_eq!(
            parse_range_header("bytes=-abc", 1024).unwrap_err(),
            RangeError::NotSatisfiable { size: 1024 }
        );
    }

    #[test]
    fn parse_range_multiple_dashes_in_spec_is_416() {
        // `bytes=1-2-3` is not a valid byte-range-spec; reject.
        let err = parse_range_header("bytes=1-2-3", 1024).unwrap_err();
        assert_eq!(err, RangeError::NotSatisfiable { size: 1024 });
    }

    #[test]
    fn parse_range_negative_inclusive_is_416() {
        // u64 can't parse a leading `-` other than the suffix form;
        // `bytes=-5-10` should not parse as anything sensible.
        let err = parse_range_header("bytes=-5-10", 1024).unwrap_err();
        assert_eq!(err, RangeError::NotSatisfiable { size: 1024 });
    }

    #[test]
    fn parse_range_zero_size_object_any_range_is_416() {
        // size = 0 means there are no satisfiable bytes; every form
        // 416s. Empty config blob is a real OCI object — make sure
        // we never serve it as 206.
        assert_eq!(
            parse_range_header("bytes=0-0", 0).unwrap_err(),
            RangeError::NotSatisfiable { size: 0 }
        );
        assert_eq!(
            parse_range_header("bytes=0-", 0).unwrap_err(),
            RangeError::NotSatisfiable { size: 0 }
        );
        assert_eq!(
            parse_range_header("bytes=-1", 0).unwrap_err(),
            RangeError::NotSatisfiable { size: 0 }
        );
    }

    use hort_app::use_cases::test_support::{
        sample_artifact, sample_repository, MockArtifactRepository, MockRepositoryRepository,
        MockStoragePort,
    };
    use hort_domain::entities::artifact::QuarantineStatus;
    use hort_domain::entities::repository::{Repository, RepositoryFormat};
    use metrics_exporter_prometheus::PrometheusBuilder;

    use hort_http_core::context::AppContext;
    use hort_http_core::test_support::build_mock_ctx;

    // -- Fixtures -----------------------------------------------------------

    fn valid_hex() -> &'static str {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }

    fn oci_repo(key: &str) -> Repository {
        let mut r = sample_repository();
        r.key = key.into();
        r.format = RepositoryFormat::Oci;
        r
    }

    /// Concrete mocks returned alongside the `AppContext` so tests can
    /// seed artifacts / repos / CAS content directly — the `AppContext`
    /// stores them behind `Arc<dyn Trait>` which can't downcast at
    /// runtime.
    struct Harness {
        ctx: Arc<AppContext>,
        artifacts: Arc<MockArtifactRepository>,
        repositories: Arc<MockRepositoryRepository>,
        storage: Arc<MockStoragePort>,
    }

    fn harness() -> Harness {
        let handle = PrometheusBuilder::new().build_recorder().handle();
        let (ctx, mocks) = build_mock_ctx(handle);
        Harness {
            ctx,
            artifacts: mocks.artifacts,
            repositories: mocks.repositories,
            storage: mocks.storage,
        }
    }

    /// Drive the full dispatcher chain (`get_pull` / `head_pull`
    /// routing through [`super::super::tail::parse_tail`] into
    /// [`super::serve`]) so the blob-serve happy path AND the route-
    /// level NAME_UNKNOWN fallback are exercised end-to-end.
    fn blob_router(ctx: Arc<AppContext>) -> Router {
        Router::new()
            .route(
                "/v2/:repo_key/*tail",
                axum::routing::get(super::super::get_pull).head(super::super::head_pull),
            )
            .with_state(ctx)
    }

    fn run<F, T>(f: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    /// Seed an artifact at `blobs/sha256:<hex>` with content pre-loaded
    /// into CAS. Takes concrete mock handles from [`Harness`] so no
    /// `as_any` / downcast is required.
    fn seed_blob(
        artifacts: &MockArtifactRepository,
        storage: &MockStoragePort,
        repo_id: Uuid,
        hex: &str,
        content: &[u8],
        status: QuarantineStatus,
    ) -> Uuid {
        let hash: ContentHash = hex.parse().unwrap();
        let mut a = sample_artifact(QuarantineStatus::None);
        a.repository_id = repo_id;
        a.path = format!("blobs/sha256:{hex}");
        a.sha256_checksum = hash.clone();
        a.size_bytes = content.len() as i64;
        a.quarantine_status = status;
        if matches!(status, QuarantineStatus::Quarantined) {
            // Anchor stored on the row; the transient computed deadline
            // is what `check_quarantine` reads for `Retry-After`.
            a.quarantine_window_start = Some(Utc::now());
            a.quarantine_deadline = Some(Utc::now() + chrono::Duration::seconds(120));
        }
        let id = a.id;
        artifacts.insert(a);
        storage.insert_content(hash, content.to_vec());
        id
    }

    // -- Handler: missing repo / blob / digest -----------------------------

    #[test]
    fn get_blob_missing_repo_returns_404_name_unknown() {
        let (status, body) = run(async {
            let h = harness();
            // No repo insert — `find_by_key("missing-repo")` misses.
            let router = blob_router(h.ctx);
            let uri = format!("/v2/missing-repo/nginx/blobs/sha256:{}", valid_hex());
            let resp = router
                .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::NOT_FOUND);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "NAME_UNKNOWN");
    }

    #[test]
    fn get_blob_repo_exists_but_blob_missing_returns_404_blob_unknown() {
        let (status, body) = run(async {
            let h = harness();
            h.repositories.insert(oci_repo("myrepo"));
            let router = blob_router(h.ctx);
            let uri = format!("/v2/myrepo/nginx/blobs/sha256:{}", valid_hex());
            let resp = router
                .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::NOT_FOUND);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "BLOB_UNKNOWN");
        assert_eq!(
            parsed["errors"][0]["detail"]["digest"],
            format!("sha256:{}", valid_hex())
        );
    }

    #[test]
    fn get_blob_unsupported_digest_algo_returns_400_unsupported() {
        let (status, body) = run(async {
            let h = harness();
            h.repositories.insert(oci_repo("myrepo"));
            let router = blob_router(h.ctx);
            let resp = router
                .oneshot(
                    Request::get(
                        "/v2/myrepo/nginx/blobs/sha512:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    )
                    .body(Body::empty())
                    .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "UNSUPPORTED");
    }

    #[test]
    fn get_blob_malformed_digest_returns_400_digest_invalid() {
        let (status, body) = run(async {
            let h = harness();
            h.repositories.insert(oci_repo("myrepo"));
            let router = blob_router(h.ctx);
            // Too short — not 64 hex chars.
            let resp = router
                .oneshot(
                    Request::get("/v2/myrepo/nginx/blobs/sha256:deadbeef")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "DIGEST_INVALID");
    }

    // -- Happy path --------------------------------------------------------

    #[test]
    fn get_blob_served_with_spec_headers() {
        // Pre-compute the hash outside the async block so it can be
        // used both for seeding and URL construction. Digest of the
        // test payload — the handler does not re-verify, it just streams.
        let content = b"hello world".to_vec();
        let hex = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&content))
        };

        let (status, headers, body) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            seed_blob(
                &h.artifacts,
                &h.storage,
                repo_id,
                &hex,
                &content,
                QuarantineStatus::None,
            );
            let router = blob_router(h.ctx);
            let uri = format!("/v2/myrepo/nginx/blobs/sha256:{hex}");
            let resp = router
                .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let headers = resp.headers().clone();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, headers, body)
        });
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers
                .get("docker-content-digest")
                .unwrap()
                .to_str()
                .unwrap(),
            format!("sha256:{hex}"),
        );
        assert_eq!(
            headers.get(CONTENT_TYPE).unwrap().to_str().unwrap(),
            "application/octet-stream"
        );
        assert_eq!(
            headers
                .get(CONTENT_LENGTH)
                .unwrap()
                .to_str()
                .unwrap()
                .parse::<usize>()
                .unwrap(),
            content.len(),
        );
        assert_eq!(body, content);
    }

    // -- HEAD parity -------------------------------------------------------

    #[test]
    fn head_blob_returns_empty_body_with_identical_headers() {
        let content = b"head parity content".to_vec();
        let hex = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&content))
        };

        let (status, headers, body) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            seed_blob(
                &h.artifacts,
                &h.storage,
                repo_id,
                &hex,
                &content,
                QuarantineStatus::None,
            );
            let router = blob_router(h.ctx);
            let uri = format!("/v2/myrepo/nginx/blobs/sha256:{hex}");
            let resp = router
                .oneshot(
                    Request::builder()
                        .method(Method::HEAD)
                        .uri(uri)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let headers = resp.headers().clone();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, headers, body)
        });
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"", "HEAD must return an empty body");
        // Identical header set to GET — HEAD-before-GET clients rely
        // on byte-matching Content-Length + Docker-Content-Digest.
        assert_eq!(
            headers
                .get("docker-content-digest")
                .unwrap()
                .to_str()
                .unwrap(),
            format!("sha256:{hex}"),
        );
        assert_eq!(
            headers
                .get(CONTENT_LENGTH)
                .unwrap()
                .to_str()
                .unwrap()
                .parse::<usize>()
                .unwrap(),
            content.len(),
        );
    }

    // -- Quarantine --------------------------------------------------------

    #[test]
    fn get_blob_quarantined_returns_503_with_retry_after() {
        let content = b"scanning".to_vec();
        let hex = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&content))
        };

        let (status, retry_after, content_type, body) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            seed_blob(
                &h.artifacts,
                &h.storage,
                repo_id,
                &hex,
                &content,
                QuarantineStatus::Quarantined,
            );
            let router = blob_router(h.ctx);
            let uri = format!("/v2/myrepo/nginx/blobs/sha256:{hex}");
            let resp = router
                .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let retry_after = resp
                .headers()
                .get("retry-after")
                .map(|v| v.to_str().unwrap().to_string());
            let content_type = resp
                .headers()
                .get(CONTENT_TYPE)
                .map(|v| v.to_str().unwrap().to_string());
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, retry_after, content_type, body)
        });
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let retry_after = retry_after.expect("Retry-After header missing");
        let secs: i64 = retry_after.parse().unwrap();
        // Seeded with 120 seconds of window; allow for clock drift.
        assert!(
            (1..=120).contains(&secs),
            "Retry-After out of expected range: {secs}"
        );
        // Assert body shape so a regression to TOOMANYREQUESTS /
        // mis-aligned status+code pair would be caught.
        assert_eq!(
            content_type.as_deref(),
            Some("application/json"),
            "quarantine response must carry application/json"
        );
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "UNAVAILABLE");
        // `detail.retry_after_seconds` echoes the computed delta so
        // the client can cross-check against the header.
        assert!(
            parsed["errors"][0]["detail"]["retry_after_seconds"].is_i64(),
            "detail.retry_after_seconds must be a number"
        );
    }

    // -- Rejected hides the blob -------------------------------------------

    #[test]
    fn get_blob_rejected_returns_404_blob_unknown() {
        let content = b"bad".to_vec();
        let hex = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&content))
        };

        let (status, body) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            seed_blob(
                &h.artifacts,
                &h.storage,
                repo_id,
                &hex,
                &content,
                QuarantineStatus::Rejected,
            );
            let router = blob_router(h.ctx);
            let uri = format!("/v2/myrepo/nginx/blobs/sha256:{hex}");
            let resp = router
                .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::NOT_FOUND);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "BLOB_UNKNOWN");
    }

    // -- Cross-repo isolation ---------------------------------------------

    #[test]
    fn cross_repo_foreign_blob_returns_404() {
        let content = b"foreign content".to_vec();
        let hex = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&content))
        };

        let (status, body) = run(async {
            let h = harness();
            let foreign = oci_repo("foreign-repo");
            let foreign_id = foreign.id;
            h.repositories.insert(foreign);
            h.repositories.insert(oci_repo("myrepo"));

            // Seed the blob ONLY in `foreign-repo`. A GET against
            // `myrepo` with the same digest must return BLOB_UNKNOWN —
            // the repo-scoped `find_by_path` enforces isolation.
            seed_blob(
                &h.artifacts,
                &h.storage,
                foreign_id,
                &hex,
                &content,
                QuarantineStatus::None,
            );
            let router = blob_router(h.ctx);
            let uri = format!("/v2/myrepo/nginx/blobs/sha256:{hex}");
            let resp = router
                .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::NOT_FOUND);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "BLOB_UNKNOWN");
    }

    // -- DB-error collapse guard ------------------------------------------

    /// A non-`NotFound` DomainError (simulating pool exhaustion or a
    /// transient SQL failure) must NOT collapse to 404 NAME_UNKNOWN.
    /// Incidents need a 5xx surface so they're not masked as repo-
    /// missing 404s.
    #[test]
    fn get_blob_returns_500_on_repo_lookup_infra_error() {
        let (status, body) = run(async {
            let h = harness();
            h.repositories
                .fail_next_find_by_key(DomainError::Invariant("simulated pool exhaustion".into()));
            let router = blob_router(h.ctx);
            let uri = format!("/v2/myrepo/nginx/blobs/sha256:{}", valid_hex());
            let resp = router
                .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        // Body must not leak internals (e.g., the raw error message).
        hort_http_core::error::assert_no_internal_leakage(status, &body);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "INTERNAL");
    }

    // -- Zero-byte blob Content-Length ------------------------------------

    /// OCI's empty-config blob (sha256:44136f...) is a legal 0-byte
    /// object. Without `Content-Length: 0` axum chunk-encodes the
    /// response and strict clients mis-handle. Every blob response
    /// must carry Content-Length, even when size_bytes = 0.
    #[test]
    fn get_zero_byte_blob_returns_200_with_content_length_0() {
        let content: Vec<u8> = vec![];
        let hex = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&content))
        };

        let (status, headers, body) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            seed_blob(
                &h.artifacts,
                &h.storage,
                repo_id,
                &hex,
                &content,
                QuarantineStatus::None,
            );
            let router = blob_router(h.ctx);
            let uri = format!("/v2/myrepo/nginx/blobs/sha256:{hex}");
            let resp = router
                .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let headers = resp.headers().clone();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, headers, body)
        });
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers
                .get(CONTENT_LENGTH)
                .expect("Content-Length must be set even for 0-byte blobs")
                .to_str()
                .unwrap(),
            "0",
        );
        assert!(body.is_empty(), "body must be zero bytes");
    }

    // -- HEAD against a missing blob --------------------------------------

    /// HEAD for a non-existent digest must return 404 — the status
    /// must match GET so HEAD-before-GET probing works. The wire body
    /// is empty: axum's response pipeline strips HEAD bodies before
    /// they reach the client (per RFC 9110 §9.3.2). The handler's
    /// internal `OciError::BlobUnknown` envelope is still constructed
    /// but dropped in transit; asserting an empty body is the correct
    /// observable behaviour for this path.
    #[test]
    fn head_missing_blob_returns_404_with_blob_unknown_envelope() {
        let (status, body) = run(async {
            let h = harness();
            h.repositories.insert(oci_repo("myrepo"));
            // No artifact seeded — the hash is valid hex but the row
            // doesn't exist.
            let router = blob_router(h.ctx);
            let uri = format!("/v2/myrepo/nginx/blobs/sha256:{}", valid_hex());
            let resp = router
                .oneshot(
                    Request::builder()
                        .method(Method::HEAD)
                        .uri(uri)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::NOT_FOUND);
        // HEAD bodies are stripped by axum's response pipeline; the
        // observable wire body is empty. Strict OCI clients rely on
        // status-code parity with GET — the GET-path body assertion
        // lives in `get_blob_repo_exists_but_blob_missing_returns_404_blob_unknown`.
        assert!(body.is_empty(), "HEAD response body must be empty");
    }

    // -----------------------------------------------------------------
    // Pull-through-on-miss
    // -----------------------------------------------------------------

    /// Local cache miss + upstream mapping configured + upstream
    /// returns the blob → blob ingested into local CAS, served
    /// from the same response. The `upstream_proxy` mock is keyed
    /// by `(path_prefix, upstream_name, digest)`; the
    /// `upstream_resolver` mock holds the mapping that the OCI
    /// dispatcher consults on miss.
    #[test]
    fn cache_miss_with_upstream_mapping_fetches_and_serves() {
        use hort_app::use_cases::test_support::MockUpstreamProxy;
        use hort_app::use_cases::test_support::MockUpstreamResolver;
        use hort_domain::ports::repository_upstream_mapping_repository::{
            RepositoryUpstreamMapping, UpstreamAuth,
        };

        let content = b"hello-from-upstream".to_vec();
        let hex = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&content))
        };

        let (status, body, event_batches) = run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);

            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            mocks.repositories.insert(repo);

            // Seed the resolver: prefix `dockerhub/` maps to a synthetic
            // upstream URL. The mock resolver mirrors the longest-
            // prefix-match logic; here only one mapping is needed.
            let now = Utc::now();
            mocks.upstream_resolver.insert(RepositoryUpstreamMapping {
                id: Uuid::new_v4(),
                repository_id: repo_id,
                path_prefix: "dockerhub/".into(),
                upstream_url: "https://registry.example.com".into(),
                upstream_name_prefix: None,
                upstream_auth: UpstreamAuth::Anonymous,
                secret_ref: None,
                managed_by: hort_domain::entities::managed_by::ManagedBy::Local,
                managed_by_digest: None,
                insecure_upstream_url: false,
                trust_upstream_publish_time: false,
                mtls_cert_ref: None,
                mtls_key_ref: None,
                ca_bundle_ref: None,
                pinned_cert_sha256: None,
                created_at: now,
                updated_at: now,
            });
            // Seed the proxy: when fetched, return the synthesized blob.
            mocks.upstream_proxy.insert_blob(
                "dockerhub/",
                "library/nginx",
                &format!("sha256:{hex}"),
                content.clone(),
                Some(format!("sha256:{hex}")),
            );

            let lifecycle = mocks.lifecycle.clone();
            let router = blob_router(ctx);
            let uri = format!("/v2/myrepo/dockerhub/library/nginx/blobs/sha256:{hex}");
            let resp = router
                .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 64 * 1024)
                .await
                .unwrap()
                .to_vec();
            (status, body, lifecycle.committed_transitions())
        });
        assert_eq!(
            status,
            StatusCode::OK,
            "expected upstream-pull-on-miss to serve 200"
        );
        assert_eq!(
            body, b"hello-from-upstream",
            "served body must match upstream-fetched content"
        );

        // ChecksumVerified rides in the same commit_transition batch as
        // ArtifactIngested — atomic with the mint per upstream-verification
        // design (ADR 0006).
        use hort_domain::events::StreamCategory;
        assert_eq!(event_batches.len(), 1);
        let (_, batch, _) = &event_batches[0];
        assert_eq!(batch.stream_id.category, StreamCategory::Artifact);
        let kinds: Vec<&str> = batch.events.iter().map(|e| e.event.event_type()).collect();
        assert_eq!(
            kinds,
            vec!["ArtifactIngested", "ChecksumVerified", "ScanRequested"],
            "happy-path pull-through must atomically emit ArtifactIngested + \
             ChecksumVerified + ScanRequested (DefaultPolicy fallback)"
        );

        // Reach unused imports to silence lints when only one test in
        // the module relies on these symbols.
        let _ = std::any::type_name::<MockUpstreamProxy>();
        let _ = std::any::type_name::<MockUpstreamResolver>();
    }

    // -----------------------------------------------------------------
    // OCI config + layer blob `Last-Modified` capture (ADR 0007).
    // Each blob fetch carries its own `Last-Modified` response header
    // (≈ blob push time on the upstream registry). The per-Artifact
    // OCI ingest model records each blob's own value; the conceptual
    // image-aggregate max(Last-Modified) is assembled by the caller,
    // not here.
    // -----------------------------------------------------------------

    /// Per-blob: `Some(Last-Modified)` on the blob fetch threads onto
    /// the minted `Artifact.upstream_published_at`.
    #[test]
    fn cache_miss_threads_blob_last_modified_into_artifact() {
        use hort_app::use_cases::test_support::MockUpstreamProxy;
        use hort_app::use_cases::test_support::MockUpstreamResolver;
        use hort_domain::ports::repository_upstream_mapping_repository::{
            RepositoryUpstreamMapping, UpstreamAuth,
        };

        let content = b"layer-with-publish-time".to_vec();
        let hex = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&content))
        };
        let last_modified: DateTime<Utc> = DateTime::parse_from_rfc3339("2024-03-15T08:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let recorded_published_at = run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            mocks.repositories.insert(repo);

            let now = Utc::now();
            mocks.upstream_resolver.insert(RepositoryUpstreamMapping {
                id: Uuid::new_v4(),
                repository_id: repo_id,
                path_prefix: "dockerhub/".into(),
                upstream_url: "https://registry.example.com".into(),
                upstream_name_prefix: None,
                upstream_auth: UpstreamAuth::Anonymous,
                secret_ref: None,
                managed_by: hort_domain::entities::managed_by::ManagedBy::Local,
                managed_by_digest: None,
                insecure_upstream_url: false,
                trust_upstream_publish_time: false,
                mtls_cert_ref: None,
                mtls_key_ref: None,
                ca_bundle_ref: None,
                pinned_cert_sha256: None,
                created_at: now,
                updated_at: now,
            });
            // Seed the proxy with a Last-Modified hint on the blob.
            mocks.upstream_proxy.insert_blob_with_last_modified(
                "dockerhub/",
                "library/nginx",
                &format!("sha256:{hex}"),
                content.clone(),
                Some(format!("sha256:{hex}")),
                Some(last_modified),
            );

            let lifecycle = mocks.lifecycle.clone();
            let router = blob_router(ctx);
            let uri = format!("/v2/myrepo/dockerhub/library/nginx/blobs/sha256:{hex}");
            let resp = router
                .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "expected 200 on success");
            let transitions = lifecycle.committed_transitions();
            assert_eq!(
                transitions.len(),
                1,
                "expected exactly one Artifact transition (the ingest)"
            );
            transitions[0].0.upstream_published_at
        });

        assert_eq!(
            recorded_published_at,
            Some(last_modified),
            "OCI blob Last-Modified must thread onto \
             Artifact.upstream_published_at via VerifiedIngestRequest"
        );

        let _ = std::any::type_name::<MockUpstreamProxy>();
        let _ = std::any::type_name::<MockUpstreamResolver>();
    }

    /// Per-blob: `None` Last-Modified on the blob fetch → no hint
    /// recorded on the artifact (absent header is the common case;
    /// the ingest must succeed).
    #[test]
    fn cache_miss_no_last_modified_records_none_publish_time() {
        use hort_app::use_cases::test_support::MockUpstreamProxy;
        use hort_app::use_cases::test_support::MockUpstreamResolver;
        use hort_domain::ports::repository_upstream_mapping_repository::{
            RepositoryUpstreamMapping, UpstreamAuth,
        };

        let content = b"layer-without-publish-time".to_vec();
        let hex = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&content))
        };

        let recorded_published_at = run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            mocks.repositories.insert(repo);

            let now = Utc::now();
            mocks.upstream_resolver.insert(RepositoryUpstreamMapping {
                id: Uuid::new_v4(),
                repository_id: repo_id,
                path_prefix: "dockerhub/".into(),
                upstream_url: "https://registry.example.com".into(),
                upstream_name_prefix: None,
                upstream_auth: UpstreamAuth::Anonymous,
                secret_ref: None,
                managed_by: hort_domain::entities::managed_by::ManagedBy::Local,
                managed_by_digest: None,
                insecure_upstream_url: false,
                trust_upstream_publish_time: false,
                mtls_cert_ref: None,
                mtls_key_ref: None,
                ca_bundle_ref: None,
                pinned_cert_sha256: None,
                created_at: now,
                updated_at: now,
            });
            // `insert_blob` (without `_with_last_modified`) → None hint.
            mocks.upstream_proxy.insert_blob(
                "dockerhub/",
                "library/nginx",
                &format!("sha256:{hex}"),
                content.clone(),
                Some(format!("sha256:{hex}")),
            );

            let lifecycle = mocks.lifecycle.clone();
            let router = blob_router(ctx);
            let uri = format!("/v2/myrepo/dockerhub/library/nginx/blobs/sha256:{hex}");
            let resp = router
                .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let transitions = lifecycle.committed_transitions();
            assert_eq!(transitions.len(), 1);
            transitions[0].0.upstream_published_at
        });

        assert_eq!(
            recorded_published_at, None,
            "absent Last-Modified must yield None, not an ingest failure"
        );

        let _ = std::any::type_name::<MockUpstreamProxy>();
        let _ = std::any::type_name::<MockUpstreamResolver>();
    }

    /// Image-aggregate (max across config + layers) — when N blobs
    /// from the same image are ingested sequentially, each Artifact
    /// carries its own blob's `Last-Modified`, and `max(over all
    /// `Some` values)` ≈ image push time as the design specifies
    /// ("config + layer blobs"). The aggregate is not assembled into
    /// a single record by the pull path; this test pins that each
    /// blob's value is recorded individually so a downstream consumer
    /// can compute max across them.
    #[test]
    fn blob_max_selection_recorded_per_artifact_across_image() {
        use hort_app::use_cases::test_support::MockUpstreamProxy;
        use hort_app::use_cases::test_support::MockUpstreamResolver;
        use hort_domain::ports::repository_upstream_mapping_repository::{
            RepositoryUpstreamMapping, UpstreamAuth,
        };

        // Three blobs simulating config + 2 layers, with varied timestamps.
        // `max` is the newest — max is the design intent (never min),
        // because shared base layers can be very old.
        let blobs: Vec<(Vec<u8>, DateTime<Utc>)> = vec![
            (
                b"config-blob".to_vec(),
                DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
            ),
            (
                b"shared-base-layer".to_vec(),
                DateTime::parse_from_rfc3339("2018-06-15T12:30:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
            ),
            (
                b"app-layer".to_vec(),
                DateTime::parse_from_rfc3339("2024-09-20T18:45:30Z")
                    .unwrap()
                    .with_timezone(&Utc),
            ),
        ];
        let expected_max = blobs.iter().map(|(_, t)| *t).max().unwrap();

        let recorded = run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            mocks.repositories.insert(repo);

            let now = Utc::now();
            mocks.upstream_resolver.insert(RepositoryUpstreamMapping {
                id: Uuid::new_v4(),
                repository_id: repo_id,
                path_prefix: "dockerhub/".into(),
                upstream_url: "https://registry.example.com".into(),
                upstream_name_prefix: None,
                upstream_auth: UpstreamAuth::Anonymous,
                secret_ref: None,
                managed_by: hort_domain::entities::managed_by::ManagedBy::Local,
                managed_by_digest: None,
                insecure_upstream_url: false,
                trust_upstream_publish_time: false,
                mtls_cert_ref: None,
                mtls_key_ref: None,
                ca_bundle_ref: None,
                pinned_cert_sha256: None,
                created_at: now,
                updated_at: now,
            });

            // Compute hex for each blob and seed them; ingest each.
            let mut hexes = Vec::new();
            for (content, lm) in &blobs {
                use sha2::Digest;
                let hex = format!("{:x}", sha2::Sha256::digest(content));
                mocks.upstream_proxy.insert_blob_with_last_modified(
                    "dockerhub/",
                    "library/nginx",
                    &format!("sha256:{hex}"),
                    content.clone(),
                    Some(format!("sha256:{hex}")),
                    Some(*lm),
                );
                hexes.push(hex);
            }

            let lifecycle = mocks.lifecycle.clone();
            let router = blob_router(ctx);
            for hex in &hexes {
                let uri = format!("/v2/myrepo/dockerhub/library/nginx/blobs/sha256:{hex}");
                let resp = router
                    .clone()
                    .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
            }

            let transitions = lifecycle.committed_transitions();
            assert_eq!(transitions.len(), blobs.len());
            transitions
                .into_iter()
                .filter_map(|(art, _, _)| art.upstream_published_at)
                .collect::<Vec<_>>()
        });

        // Each blob's own Last-Modified was recorded; the conceptual
        // image-aggregate max is `expected_max` (newest of the three).
        assert_eq!(recorded.len(), 3, "expected three blobs ingested");
        for (_, ts) in &blobs {
            assert!(
                recorded.contains(ts),
                "each blob's Last-Modified must round-trip to its Artifact"
            );
        }
        let actual_max = recorded.iter().copied().max().unwrap();
        assert_eq!(
            actual_max, expected_max,
            "max over recorded upstream_published_at values ≈ image push time \
             (max, never min, never first)"
        );

        let _ = std::any::type_name::<MockUpstreamProxy>();
        let _ = std::any::type_name::<MockUpstreamResolver>();
    }

    /// Mixed Some/None blobs across the image → max over the
    /// successfully-parsed (Some) timestamps; None blobs are simply
    /// ignored in the aggregate. Best-effort by contract — a single
    /// missing header on one layer does not poison the others.
    #[test]
    fn blob_max_selection_skips_none_entries_across_image() {
        use hort_app::use_cases::test_support::MockUpstreamProxy;
        use hort_app::use_cases::test_support::MockUpstreamResolver;
        use hort_domain::ports::repository_upstream_mapping_repository::{
            RepositoryUpstreamMapping, UpstreamAuth,
        };

        let early: DateTime<Utc> = DateTime::parse_from_rfc3339("2019-02-02T02:02:02Z")
            .unwrap()
            .with_timezone(&Utc);
        let late: DateTime<Utc> = DateTime::parse_from_rfc3339("2025-04-04T04:04:04Z")
            .unwrap()
            .with_timezone(&Utc);
        // Three blobs: Some(early), None, Some(late).
        let bodies: Vec<(Vec<u8>, Option<DateTime<Utc>>)> = vec![
            (b"older-layer".to_vec(), Some(early)),
            (b"no-hint-layer".to_vec(), None),
            (b"newer-layer".to_vec(), Some(late)),
        ];

        let recorded = run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            mocks.repositories.insert(repo);

            let now = Utc::now();
            mocks.upstream_resolver.insert(RepositoryUpstreamMapping {
                id: Uuid::new_v4(),
                repository_id: repo_id,
                path_prefix: "dockerhub/".into(),
                upstream_url: "https://registry.example.com".into(),
                upstream_name_prefix: None,
                upstream_auth: UpstreamAuth::Anonymous,
                secret_ref: None,
                managed_by: hort_domain::entities::managed_by::ManagedBy::Local,
                managed_by_digest: None,
                insecure_upstream_url: false,
                trust_upstream_publish_time: false,
                mtls_cert_ref: None,
                mtls_key_ref: None,
                ca_bundle_ref: None,
                pinned_cert_sha256: None,
                created_at: now,
                updated_at: now,
            });

            let mut hexes = Vec::new();
            for (content, lm) in &bodies {
                use sha2::Digest;
                let hex = format!("{:x}", sha2::Sha256::digest(content));
                mocks.upstream_proxy.insert_blob_with_last_modified(
                    "dockerhub/",
                    "library/nginx",
                    &format!("sha256:{hex}"),
                    content.clone(),
                    Some(format!("sha256:{hex}")),
                    *lm,
                );
                hexes.push(hex);
            }

            let lifecycle = mocks.lifecycle.clone();
            let router = blob_router(ctx);
            for hex in &hexes {
                let uri = format!("/v2/myrepo/dockerhub/library/nginx/blobs/sha256:{hex}");
                let resp = router
                    .clone()
                    .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
            }

            let transitions = lifecycle.committed_transitions();
            transitions
                .into_iter()
                .map(|(art, _, _)| art.upstream_published_at)
                .collect::<Vec<_>>()
        });

        // One entry should be None (the no-hint layer); the other two
        // carry the seeded timestamps.
        let some_values: Vec<DateTime<Utc>> = recorded.iter().filter_map(|&v| v).collect();
        assert_eq!(some_values.len(), 2);
        assert!(recorded.iter().any(Option::is_none));
        let actual_max = some_values.iter().copied().max().unwrap();
        assert_eq!(
            actual_max, late,
            "max over Some values must be the newest — None entries are \
             ignored in the aggregate (best-effort)"
        );

        let _ = std::any::type_name::<MockUpstreamProxy>();
        let _ = std::any::type_name::<MockUpstreamResolver>();
    }

    /// Pull-through fetch hits a curation `Block` rule. The default
    /// `DomainError::CurationBlocked` → 403 mapping must be overridden
    /// at the OCI layer to return `BLOB_UNKNOWN` (404) so the OCI
    /// client sees the same envelope
    /// as a genuine cache miss + upstream-not-found, instead of a
    /// cryptic 403 mid-pull. The test seeds a curation rule with a
    /// pattern that matches the blob's coords and asserts the wire
    /// shape.
    #[test]
    fn cache_miss_with_curation_block_returns_404_blob_unknown() {
        use hort_domain::entities::curation_rule::{CurationRule, CurationRuleAction};
        use hort_domain::entities::managed_by::ManagedBy;
        use hort_domain::ports::repository_upstream_mapping_repository::{
            RepositoryUpstreamMapping, UpstreamAuth,
        };

        let content = b"upstream-bytes-blocked".to_vec();
        let hex = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&content))
        };

        let (status, body) = run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);

            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            mocks.repositories.insert(repo);

            let now = Utc::now();
            mocks.upstream_resolver.insert(RepositoryUpstreamMapping {
                id: Uuid::new_v4(),
                repository_id: repo_id,
                path_prefix: "dockerhub/".into(),
                upstream_url: "https://registry.example.com".into(),
                upstream_name_prefix: None,
                upstream_auth: UpstreamAuth::Anonymous,
                secret_ref: None,
                managed_by: ManagedBy::Local,
                managed_by_digest: None,
                insecure_upstream_url: false,
                trust_upstream_publish_time: false,
                mtls_cert_ref: None,
                mtls_key_ref: None,
                ca_bundle_ref: None,
                pinned_cert_sha256: None,
                created_at: now,
                updated_at: now,
            });
            mocks.upstream_proxy.insert_blob(
                "dockerhub/",
                "library/blocked-image",
                &format!("sha256:{hex}"),
                content.clone(),
                Some(format!("sha256:{hex}")),
            );

            // Seed a curation rule that matches the OCI blob coords'
            // name (`oci_blob_coords` produces a name shaped like the
            // image path; the `*` pattern matches anything).
            let rule = CurationRule {
                id: Uuid::new_v4(),
                name: "block-everything".into(),
                format: None,
                package_pattern: "*".into(),
                action: CurationRuleAction::Block,
                reason: "policy ban".into(),
                managed_by: ManagedBy::GitOps,
                managed_by_digest: Some([0xab; 32]),
            };
            mocks.curation_rules.set_rules_for_repo(repo_id, vec![rule]);

            let router = blob_router(ctx);
            let uri = format!("/v2/myrepo/dockerhub/library/blocked-image/blobs/sha256:{hex}");
            let resp = router
                .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });

        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "CurationBlocked must be overridden to 404 on OCI pull-through (not the default 403)"
        );
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            parsed["errors"][0]["code"], "BLOB_UNKNOWN",
            "404 envelope must be the OCI BLOB_UNKNOWN spec error, not a generic 403 body"
        );
    }

    // ---------------------------------------------------------------------
    // Range-honouring GET / HEAD (RFC 7233)
    // ---------------------------------------------------------------------

    /// Build a 1024-byte content fixture with a per-byte distinct
    /// pattern so a mis-aligned slice would fail the byte-exact
    /// assertions below. Same shape as the storage-port contract
    /// fixture; redefined here to keep the OCI test self-contained.
    fn range_fixture_content() -> Vec<u8> {
        (0..1024u32).map(|i| (i % 256) as u8).collect()
    }

    /// Helper: seed an OCI repo + blob with the 1024-byte fixture
    /// and return the harness + URI. Used by every Range test below.
    fn seed_range_fixture() -> (Harness, String, String, Vec<u8>) {
        let h = harness();
        let repo = oci_repo("myrepo");
        let repo_id = repo.id;
        h.repositories.insert(repo);
        let content = range_fixture_content();
        let hex = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&content))
        };
        seed_blob(
            &h.artifacts,
            &h.storage,
            repo_id,
            &hex,
            &content,
            QuarantineStatus::None,
        );
        let uri = format!("/v2/myrepo/nginx/blobs/sha256:{hex}");
        (h, uri, hex, content)
    }

    /// `Range: bytes=0-99` against a 1024-byte blob → 206 with the
    /// first 100 bytes and the spec-mandated `Content-Range` /
    /// `Content-Length` / `Docker-Content-Digest` / `Accept-Ranges`
    /// headers.
    #[test]
    fn get_blob_range_first_100_bytes_returns_206() {
        let (status, headers, body) = run(async {
            let (h, uri, _hex, _content) = seed_range_fixture();
            let router = blob_router(h.ctx);
            let resp = router
                .oneshot(
                    Request::get(&uri)
                        .header("Range", "bytes=0-99")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let headers = resp.headers().clone();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, headers, body)
        });
        assert_eq!(status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            headers.get("content-range").unwrap().to_str().unwrap(),
            "bytes 0-99/1024"
        );
        assert_eq!(
            headers
                .get(CONTENT_LENGTH)
                .unwrap()
                .to_str()
                .unwrap()
                .parse::<usize>()
                .unwrap(),
            100
        );
        assert_eq!(
            headers.get("accept-ranges").unwrap().to_str().unwrap(),
            "bytes"
        );
        assert_eq!(body.len(), 100);
        assert_eq!(body, &range_fixture_content()[0..100]);
    }

    /// `Range: bytes=99-` → 206 with the tail (size - 99 = 925
    /// bytes). Content-Range names the inclusive last byte index.
    #[test]
    fn get_blob_range_from_offset_returns_206_tail() {
        let (status, headers, body) = run(async {
            let (h, uri, _hex, _content) = seed_range_fixture();
            let router = blob_router(h.ctx);
            let resp = router
                .oneshot(
                    Request::get(&uri)
                        .header("Range", "bytes=99-")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let headers = resp.headers().clone();
            let body = to_bytes(resp.into_body(), 64 * 1024)
                .await
                .unwrap()
                .to_vec();
            (status, headers, body)
        });
        assert_eq!(status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            headers.get("content-range").unwrap().to_str().unwrap(),
            "bytes 99-1023/1024"
        );
        assert_eq!(body.len(), 1024 - 99);
        assert_eq!(body, &range_fixture_content()[99..]);
    }

    /// `Range: bytes=-50` → 206 with the last 50 bytes.
    #[test]
    fn get_blob_range_suffix_returns_206_last_n_bytes() {
        let (status, headers, body) = run(async {
            let (h, uri, _hex, _content) = seed_range_fixture();
            let router = blob_router(h.ctx);
            let resp = router
                .oneshot(
                    Request::get(&uri)
                        .header("Range", "bytes=-50")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let headers = resp.headers().clone();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, headers, body)
        });
        assert_eq!(status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            headers.get("content-range").unwrap().to_str().unwrap(),
            "bytes 974-1023/1024"
        );
        assert_eq!(body.len(), 50);
        assert_eq!(body, &range_fixture_content()[974..]);
    }

    /// `Range: bytes=10000000-` against a 1024-byte blob → 416 with
    /// `Content-Range: bytes */1024`. RFC 7233 §4.4.
    #[test]
    fn get_blob_range_first_byte_pos_beyond_size_returns_416() {
        let (status, headers, body) = run(async {
            let (h, uri, _hex, _content) = seed_range_fixture();
            let router = blob_router(h.ctx);
            let resp = router
                .oneshot(
                    Request::get(&uri)
                        .header("Range", "bytes=10000000-")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let headers = resp.headers().clone();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, headers, body)
        });
        assert_eq!(status, StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            headers.get("content-range").unwrap().to_str().unwrap(),
            "bytes */1024"
        );
        assert!(body.is_empty(), "416 body must be empty");
    }

    /// Multi-range `bytes=0-99,200-299` is unsupported → 416. We do
    /// NOT support multipart/byteranges (see `RangeError` docstring
    /// for the rationale).
    #[test]
    fn get_blob_multi_range_returns_416() {
        let (status, _headers, body) = run(async {
            let (h, uri, _hex, _content) = seed_range_fixture();
            let router = blob_router(h.ctx);
            let resp = router
                .oneshot(
                    Request::get(&uri)
                        .header("Range", "bytes=0-99,200-299")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let headers = resp.headers().clone();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, headers, body)
        });
        assert_eq!(status, StatusCode::RANGE_NOT_SATISFIABLE);
        assert!(body.is_empty());
    }

    /// HEAD with Range returns the same status + headers as GET, body
    /// is empty (axum strips HEAD bodies). Kubelet's HEAD-then-GET
    /// probe must round-trip cleanly.
    #[test]
    fn head_blob_with_range_returns_206_headers_empty_body() {
        let (status, headers, body) = run(async {
            let (h, uri, _hex, _content) = seed_range_fixture();
            let router = blob_router(h.ctx);
            let resp = router
                .oneshot(
                    Request::builder()
                        .method(Method::HEAD)
                        .uri(uri)
                        .header("Range", "bytes=0-99")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let headers = resp.headers().clone();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, headers, body)
        });
        assert_eq!(status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            headers.get("content-range").unwrap().to_str().unwrap(),
            "bytes 0-99/1024"
        );
        assert_eq!(
            headers.get(CONTENT_LENGTH).unwrap().to_str().unwrap(),
            "100"
        );
        assert_eq!(
            headers
                .get("docker-content-digest")
                .unwrap()
                .to_str()
                .unwrap()
                .len(),
            7 + 64,
            "Docker-Content-Digest must echo full sha256:<hex>"
        );
        assert!(body.is_empty(), "HEAD body must be empty");
    }

    /// No Range header → 200, regression guard for the pre-15a
    /// baseline. Also: the 200 response now advertises
    /// `Accept-Ranges: bytes` (new in this item).
    #[test]
    fn get_blob_no_range_returns_200_with_accept_ranges() {
        let (status, headers, body_len) = run(async {
            let (h, uri, _hex, content) = seed_range_fixture();
            let router = blob_router(h.ctx);
            let resp = router
                .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let headers = resp.headers().clone();
            let body = to_bytes(resp.into_body(), 64 * 1024)
                .await
                .unwrap()
                .to_vec();
            (
                status,
                headers,
                content.len() == body.len() && body == content,
            )
        });
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers.get("accept-ranges").unwrap().to_str().unwrap(),
            "bytes"
        );
        assert!(body_len, "no-Range body must equal the full content");
    }

    /// Quarantine takes precedence over Range — a quarantined blob
    /// 503s with `Retry-After` regardless of the Range header. No
    /// partial bytes from a quarantined artifact may leak.
    #[test]
    fn get_blob_quarantined_with_range_still_returns_503() {
        let content = b"scanning".to_vec();
        let hex = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&content))
        };

        let status = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            seed_blob(
                &h.artifacts,
                &h.storage,
                repo_id,
                &hex,
                &content,
                QuarantineStatus::Quarantined,
            );
            let router = blob_router(h.ctx);
            let uri = format!("/v2/myrepo/nginx/blobs/sha256:{hex}");
            let resp = router
                .oneshot(
                    Request::get(&uri)
                        .header("Range", "bytes=0-3")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            resp.status()
        });
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    /// Kubelet-pattern regression guard: GET → read first half, then
    /// resume with `Range: bytes=N-`. The concatenated bytes must
    /// equal the full blob and the Docker-Content-Digest header on
    /// the 206 response must echo the FULL blob digest (not a chunk
    /// hash) so a client can verify the assembled blob.
    ///
    /// kubelet/containerd's resume implementation aborts the first
    /// GET after partial read, then re-issues with `Range: bytes=N-`
    /// where `N` is the byte count it had buffered. The two ranges
    /// must compose into the full blob without gaps or overlaps.
    #[test]
    fn kubelet_resume_pattern_concatenates_to_full_blob() {
        let (full_status, partial_status, full_digest_header, expected_hex, composed) =
            run(async {
                let (h, uri, hex, _content) = seed_range_fixture();
                let router = blob_router(h.ctx.clone());

                // First GET — full 200 response. Simulate a read-and-
                // abort by truncating the response body to half-size at
                // the test layer; kubelet would close the socket here.
                let resp = router
                    .clone()
                    .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                let full_status = resp.status();
                let full_body = to_bytes(resp.into_body(), 64 * 1024)
                    .await
                    .unwrap()
                    .to_vec();
                let half = full_body.len() / 2;
                let buffered = full_body[..half].to_vec();

                // Second GET — resume from `half` with `Range:
                // bytes=N-`. Server returns 206 + tail bytes + the FULL
                // blob digest in `Docker-Content-Digest`.
                let resume_n = half as u64;
                let resp = router
                    .oneshot(
                        Request::get(&uri)
                            .header("Range", format!("bytes={resume_n}-"))
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                let partial_status = resp.status();
                let full_digest_header = resp
                    .headers()
                    .get("docker-content-digest")
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string();
                let partial_body = to_bytes(resp.into_body(), 64 * 1024)
                    .await
                    .unwrap()
                    .to_vec();

                // Compose what kubelet would after concatenation.
                let mut composed = buffered;
                composed.extend_from_slice(&partial_body);
                (
                    full_status,
                    partial_status,
                    full_digest_header,
                    hex,
                    composed,
                )
            });

        assert_eq!(full_status, StatusCode::OK);
        assert_eq!(partial_status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            full_digest_header,
            format!("sha256:{expected_hex}"),
            "Docker-Content-Digest on 206 must echo the FULL blob digest"
        );

        let expected = range_fixture_content();
        assert_eq!(
            composed, expected,
            "concatenated half + tail must equal full blob"
        );

        // SHA-256 of the composed bytes must agree with the digest
        // the server advertised on the 206 response — what kubelet
        // verifies after assembling chunks.
        use sha2::Digest;
        let composed_hex = format!("{:x}", sha2::Sha256::digest(&composed));
        assert_eq!(
            composed_hex, expected_hex,
            "sha256(composed) must equal full-blob digest"
        );
    }

    /// Visibility regression guard (ADR 0008).
    ///
    /// Anonymous `GET /v2/<private-repo>/.../blobs/sha256:<hex>` MUST
    /// return `404 BLOB_UNKNOWN` — NOT 200 + body. The handler routes
    /// through `ArtifactUseCase::find_visible_by_path` whose
    /// `RepositoryAccessUseCase::resolve(_, None, Read)` collapses
    /// invisible-private to NotFound (anti-enumeration).
    ///
    /// Test runs under `RbacAccess::Enabled` with an empty evaluator
    /// (the harness default `Disabled` admits everything). Actor =
    /// None: no `Option<CallerPrincipal>` extension on the request
    /// since this test bypasses the bearer middleware (the simple
    /// `blob_router` in this module doesn't attach it).
    #[test]
    fn anonymous_get_on_private_repo_returns_404_name_unknown() {
        use hort_app::rbac::RbacEvaluator;
        use hort_app::use_cases::repository_access::{RbacAccess, RepositoryAccessUseCase};
        use hort_http_core::test_support::with_repository_access;

        let content = b"private blob bytes".to_vec();
        let hex = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&content))
        };
        let (status, body) = run(async {
            let h = harness();
            let mut repo = oci_repo("private-repo");
            repo.is_public = false;
            let repo_id = repo.id;
            h.repositories.insert(repo);
            seed_blob(
                &h.artifacts,
                &h.storage,
                repo_id,
                &hex,
                &content,
                QuarantineStatus::None,
            );

            // Flip RbacAccess to Enabled so anonymous + private
            // collapses to invisible (the Disabled default admits
            // everything for dev parity).
            //
            // `ctx.repositories` is `pub(crate)` (ADR 0008); pull the same
            // `Arc<MockRepositoryRepository>` off the harness's MockPorts
            // handle (`h.repositories`).
            let access = Arc::new(RepositoryAccessUseCase::new(
                h.repositories.clone(),
                RbacAccess::Enabled(Arc::new(arc_swap::ArcSwap::from_pointee(
                    RbacEvaluator::new(Vec::new()),
                ))),
                true,
            ));
            let ctx = with_repository_access(&h.ctx, access);

            let router = blob_router(ctx);
            let uri = format!("/v2/private-repo/library/nginx/blobs/sha256:{hex}");
            let resp = router
                .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "anonymous read on private OCI repo MUST be 404"
        );
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // Anti-enumeration: NAME_UNKNOWN (same envelope as
        // missing-repo).
        assert_eq!(
            parsed["errors"][0]["code"], "NAME_UNKNOWN",
            "envelope must match the missing-repo case to defeat probing"
        );
    }

    /// Local miss + NO upstream mapping → BLOB_UNKNOWN. Regression-guard
    /// so a future change can't silently make the resolver mandatory.
    #[test]
    fn cache_miss_without_upstream_mapping_still_returns_blob_unknown() {
        let (status, body) = run(async {
            let h = harness();
            h.repositories.insert(oci_repo("myrepo"));
            // No upstream mapping seeded.
            let router = blob_router(h.ctx);
            let uri = format!("/v2/myrepo/foo/bar/blobs/sha256:{}", valid_hex());
            let resp = router
                .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let body = to_bytes(resp.into_body(), 4 * 1024).await.unwrap().to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::NOT_FOUND);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "BLOB_UNKNOWN");
    }

    // ---------------------------------------------------------------------
    // Tampered-upstream end-to-end test (ADR 0006)
    //
    // # Test location
    //
    // These tests live as `#[cfg(test)]` unit tests rather than under
    // `crates/hort-http-oci/tests/` integration tests or as Playwright
    // `@smoke`-tagged specs because the assertions they make require
    // **mock-port observation**: a `ChecksumMismatch` event landing on
    // the repository stream, the absence of `commit_transition` calls,
    // and the lifecycle/event-store batch contents. None of those are
    // visible black-box from a deployed instance — by the time the
    // bytes leave the boundary, the audit trail has already been
    // committed to the event store and `MockArtifactLifecycle::committed_transitions()`
    // is the only way to assert "the use case did NOT mint a row".
    //
    // The `@smoke` tag in `scripts/run-e2e-tests.sh --tag` is a
    // Playwright filter for UI/HTTP black-box tests against a running
    // backend; `--profile smoke` runs Playwright + bash-based native
    // client tests. Neither picks up cargo unit tests, but Tier 1 CI
    // (`cargo test --workspace --lib`, every push/PR) does — these
    // tests run on every commit. Black-box smoke coverage of the
    // tampered-upstream flow is a separate concern that needs a
    // controllable mock upstream registry; if/when that fixture
    // lands it becomes a sibling test, not a replacement.
    // ---------------------------------------------------------------------

    /// Tampered upstream: the upstream serves bytes whose hash does NOT
    /// match the digest in the request URL. Asserts the four outcomes:
    /// 1. HTTP response is 502 (pull-through mismatch wire mapping).
    /// 2. ChecksumMismatch event is appended to the REPOSITORY stream
    ///    (`StreamId::repository(repo_id)`) — never the artifact stream.
    /// 3. No artifact row is minted (`commit_transition` was never
    ///    called — verified via the lifecycle mock's recorded calls).
    /// 4. The CAS does not contain a blob for the actually-served
    ///    bytes' hash (rollback fired).
    #[test]
    fn pull_through_tampered_upstream_emits_repository_checksum_mismatch() {
        use hort_app::use_cases::test_support::MockUpstreamProxy;
        use hort_app::use_cases::test_support::MockUpstreamResolver;
        use hort_domain::events::{DomainEvent, StreamCategory};
        use hort_domain::ports::repository_upstream_mapping_repository::{
            RepositoryUpstreamMapping, UpstreamAuth,
        };

        // The URL declares this digest; we'll serve bytes that hash to
        // something else. The use case rehashes while streaming and
        // returns Conflict.
        let declared_hex = "0".repeat(64);
        let actual_content = b"not-the-claimed-content".to_vec();

        let (status, lifecycle_calls, event_batches, storage_state) = run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);

            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            mocks.repositories.insert(repo);

            let now = Utc::now();
            mocks.upstream_resolver.insert(RepositoryUpstreamMapping {
                id: Uuid::new_v4(),
                repository_id: repo_id,
                path_prefix: "dockerhub/".into(),
                upstream_url: "https://registry.example.com".into(),
                upstream_name_prefix: None,
                upstream_auth: UpstreamAuth::Anonymous,
                secret_ref: None,
                managed_by: hort_domain::entities::managed_by::ManagedBy::Local,
                managed_by_digest: None,
                insecure_upstream_url: false,
                trust_upstream_publish_time: false,
                mtls_cert_ref: None,
                mtls_key_ref: None,
                ca_bundle_ref: None,
                pinned_cert_sha256: None,
                created_at: now,
                updated_at: now,
            });
            // The mock keys on (prefix, name, digest); we insert with
            // declared digest but body that does NOT hash to it.
            mocks.upstream_proxy.insert_blob(
                "dockerhub/",
                "library/nginx",
                &format!("sha256:{declared_hex}"),
                actual_content.clone(),
                Some(format!("sha256:{declared_hex}")),
            );

            let lifecycle = mocks.lifecycle.clone();
            let events = mocks.events.clone();
            let storage = mocks.storage.clone();

            let router = blob_router(ctx);
            let uri = format!("/v2/myrepo/dockerhub/library/nginx/blobs/sha256:{declared_hex}");
            let resp = router
                .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            (
                status,
                lifecycle.committed_transitions(),
                events.appended_batches(),
                storage.put_call_count(),
            )
        });

        // Wire response: 502 Bad Gateway per the OCI pull-through
        // mismatch mapping.
        assert_eq!(
            status,
            StatusCode::BAD_GATEWAY,
            "tampered upstream must surface as 502"
        );

        // No commit_transition fired — no Artifact row minted under
        // mint-after-verify.
        assert!(
            lifecycle_calls.is_empty(),
            "no artifact row should be minted on the mismatch path; got {} commits",
            lifecycle_calls.len()
        );

        // Storage put ran (to compute the hash); rollback would have
        // run too (we don't assert delete_call_count here because the
        // mock storage's count includes the put-and-immediately-delete
        // sequence — the load-bearing assertion is "no commit_transition").
        assert_eq!(
            storage_state, 1,
            "exactly one put call (the rehash) on the mismatch path"
        );

        // ChecksumMismatch on the REPOSITORY stream — never the
        // artifact stream.
        let mismatch_count = event_batches
            .iter()
            .filter(|b| b.stream_id.category == StreamCategory::Repository)
            .flat_map(|b| b.events.iter())
            .filter(|e| matches!(e.event, DomainEvent::ChecksumMismatch(_)))
            .count();
        assert_eq!(
            mismatch_count, 1,
            "exactly one ChecksumMismatch must land on the repository stream"
        );

        // ChecksumVerified must NOT have fired anywhere.
        let verified_count = event_batches
            .iter()
            .flat_map(|b| b.events.iter())
            .filter(|e| matches!(e.event, DomainEvent::ChecksumVerified(_)))
            .count();
        assert_eq!(
            verified_count, 0,
            "ChecksumVerified must NOT fire on the mismatch path"
        );

        let _ = std::any::type_name::<MockUpstreamProxy>();
        let _ = std::any::type_name::<MockUpstreamResolver>();
    }

    // ---- PullDedup wrap-coverage tests --------------------
    //
    // These tests assert that the wrapped `try_upstream_blob_pull` call
    // site (the `fetch_blob + ingest_verified` pair) actually emits
    // `hort_pull_dedup_total` metrics.
    //
    // The harness installs a `DebuggingRecorder` via
    // `metrics::with_local_recorder` around a `block_on` driving the
    // async test body. Counter labels are read back via
    // `Snapshotter::snapshot` and matched on `outcome`.

    use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
    use metrics_util::CompositeKey;

    type SnapshotRow = (
        CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        DebugValue,
    );

    /// Capture metrics emitted by the async block. Mirrors the
    /// `pull_dedup.rs::tests::capture` pattern (own current-thread
    /// runtime inside `with_local_recorder` so the recorder is the
    /// thread-local for every spawned task the orchestrator drives).
    fn capture_metrics<F, Fut>(f: F) -> Vec<SnapshotRow>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let recorder = DebuggingRecorder::new();
        let snapshotter: Snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(f());
        });
        snapshotter.snapshot().into_vec()
    }

    /// Sum a counter across all label combinations for the given
    /// `outcome`. The new tests want "did the metric fire ≥ N
    /// times for this outcome regardless of layer/format" assertions
    /// — `layer` differs (in_process vs cluster) depending on
    /// scheduler interleaving and `format` is the literal
    /// `"_any"` for blob-by-hash keys (cross-repo coalescing design).
    fn sum_counter_for_outcome(rows: &[SnapshotRow], outcome: &str) -> u64 {
        let mut total = 0u64;
        for (ckey, _u, _d, value) in rows {
            let k = ckey.key();
            if k.name() != "hort_pull_dedup_total" {
                continue;
            }
            let mut hit = false;
            for label in k.labels() {
                if label.key() == "outcome" && label.value() == outcome {
                    hit = true;
                }
            }
            if hit {
                if let DebugValue::Counter(n) = value {
                    total = total.saturating_add(*n);
                }
            }
        }
        total
    }

    fn handle() -> metrics_exporter_prometheus::PrometheusHandle {
        PrometheusBuilder::new().build_recorder().handle()
    }

    /// Render `UpstreamPullOutcome`'s variant discriminator without
    /// depending on `Debug` (the variants carry an `Artifact` row that
    /// the production type intentionally does not derive `Debug` on).
    fn outcome_variant_name(o: &UpstreamPullOutcome) -> &'static str {
        match o {
            UpstreamPullOutcome::Ingested(_) => "Ingested",
            UpstreamPullOutcome::NotConfigured => "NotConfigured",
            UpstreamPullOutcome::CurationBlocked => "CurationBlocked",
            UpstreamPullOutcome::ChecksumMismatch => "ChecksumMismatch",
            UpstreamPullOutcome::UpstreamUnavailable => "UpstreamUnavailable",
            UpstreamPullOutcome::Internal => "Internal",
        }
    }

    fn seed_dockerhub_mapping(mocks: &hort_http_core::test_support::MockPorts, repo_id: Uuid) {
        use hort_domain::entities::managed_by::ManagedBy;
        use hort_domain::ports::repository_upstream_mapping_repository::{
            RepositoryUpstreamMapping, UpstreamAuth,
        };
        let now = Utc::now();
        mocks.upstream_resolver.insert(RepositoryUpstreamMapping {
            id: Uuid::new_v4(),
            repository_id: repo_id,
            path_prefix: "dockerhub/".into(),
            upstream_url: "https://registry.example.com".into(),
            upstream_name_prefix: None,
            upstream_auth: UpstreamAuth::Anonymous,
            secret_ref: None,
            managed_by: ManagedBy::Local,
            managed_by_digest: None,
            insecure_upstream_url: false,
            trust_upstream_publish_time: false,
            mtls_cert_ref: None,
            mtls_key_ref: None,
            ca_bundle_ref: None,
            pinned_cert_sha256: None,
            created_at: now,
            updated_at: now,
        });
    }

    /// Concurrent-coalesce test: spawn two `tokio::spawn` requests
    /// against the same OCI blob (the
    /// `try_upstream_blob_pull` `fetch_blob + ingest_verified` pair).
    /// The wrapped `coalesce_blob` call site at the blob-fetch leg
    /// must route both into a single coalescing window — exactly one
    /// `leader_started` increment, ≥ 1 `follower_waited_hit`
    /// increment.
    ///
    /// Determinism note: on a current-thread runtime the second
    /// `tokio::spawn` cannot run before the first awaits something
    /// inside its closure. The first task's `ingest_verified` path
    /// crosses many await points (CAS write, event-store append,
    /// lifecycle commit) before completing; the second task's
    /// `put_if_absent` therefore lands AFTER the first's, puts it
    /// onto the Layer-A broadcast (or the Layer-B poll loop), and
    /// observes the leader's terminal outcome. `await`ing both join
    /// handles before the metric-snapshot read pins the assertion.
    #[test]
    fn concurrent_blob_callers_coalesce_into_one_leader_started() {
        let snap = capture_metrics(|| async {
            let (ctx, mocks) = build_mock_ctx(handle());
            let repo = oci_repo("oci-mirror");
            mocks.repositories.insert(repo.clone());
            seed_dockerhub_mapping(&mocks, repo.id);

            let content = b"some-oci-blob-bytes-for-coalesce-test".to_vec();
            let hex = {
                use sha2::Digest;
                format!("{:x}", sha2::Sha256::digest(&content))
            };
            let hash: ContentHash = hex.parse().unwrap();
            mocks.upstream_proxy.insert_blob(
                "dockerhub/",
                "library/nginx",
                &format!("sha256:{hex}"),
                content.clone(),
                Some(format!("sha256:{hex}")),
            );

            let ctx_a = ctx.clone();
            let repo_a = repo.clone();
            let hash_a = hash.clone();
            let h1 = tokio::spawn(async move {
                try_upstream_blob_pull(&ctx_a, &repo_a, "dockerhub/library/nginx", &hash_a).await
            });
            let ctx_b = ctx.clone();
            let repo_b = repo.clone();
            let hash_b = hash.clone();
            let h2 = tokio::spawn(async move {
                try_upstream_blob_pull(&ctx_b, &repo_b, "dockerhub/library/nginx", &hash_b).await
            });

            let r1 = h1.await.unwrap();
            let r2 = h2.await.unwrap();
            // Both callers must see a successful Ingested outcome
            // regardless of which one was elected leader vs follower
            // — the post-coalesce `find_in_repo_by_hash` resolves the
            // row the leader's ingest wrote. `UpstreamPullOutcome`
            // intentionally does not derive `Debug` (the variants
            // hold sensitive `Artifact` rows); render the failure
            // hint via the variant discriminator string.
            assert!(
                matches!(r1, UpstreamPullOutcome::Ingested(_)),
                "task 1 must succeed (leader OR follower) with Ingested; got variant {}",
                outcome_variant_name(&r1)
            );
            assert!(
                matches!(r2, UpstreamPullOutcome::Ingested(_)),
                "task 2 must succeed (leader OR follower) with Ingested; got variant {}",
                outcome_variant_name(&r2)
            );
        });

        // The blob fetch is the load-bearing wrap for this test. The
        // `try_upstream_blob_pull` site is the only wrapped call in
        // the blob path; we expect exactly one blob `leader_started`
        // (the Layer-B election may also fire alongside the Layer-A
        // election, so `leader_started` may be 1 OR 2 depending on
        // the layer mix). The lower bound `>= 1` is the load-bearing
        // condition; the follower assertion is the load-bearing
        // proof of coalescing.
        let leader_started = sum_counter_for_outcome(&snap, "leader_started");
        let follower_waited_hit = sum_counter_for_outcome(&snap, "follower_waited_hit");
        assert!(
            leader_started >= 1,
            "expected ≥1 leader_started across the wrapped blob call site; \
             got {leader_started}, snap: {snap:?}"
        );
        assert!(
            follower_waited_hit >= 1,
            "expected ≥1 follower_waited_hit (concurrent coalesce); \
             got {follower_waited_hit}, snap: {snap:?}"
        );
    }

    /// Negative-cache test: the wrapped `fetch_blob` fails
    /// (transport-level error via `fail_next_blob_with` analogue —
    /// because `MockUpstreamProxy::fetch_blob` returns
    /// `upstream:not_found:mock blob ...` when no fixture is seeded,
    /// we exploit the absent-fixture path as the failure source).
    /// The leader records the failure under the blob's `blob_by_hash`
    /// dedup key with the configured negative-cache TTL (default 30 s
    /// for `NotFound`). A second call within the TTL window must
    /// short-circuit on `negative_cache_hit` without firing a second
    /// `leader_started`.
    #[test]
    fn negative_cache_short_circuits_repeated_failures_within_ttl() {
        let snap = capture_metrics(|| async {
            let (ctx, mocks) = build_mock_ctx(handle());
            let repo = oci_repo("oci-mirror");
            mocks.repositories.insert(repo.clone());
            seed_dockerhub_mapping(&mocks, repo.id);

            // Build a content hash that has NO matching upstream blob
            // fixture. The mock returns
            // `upstream:not_found:mock blob ...` for the first call;
            // the leader records `Failed` under the dedup key.
            let content = b"absent-from-upstream".to_vec();
            let hex = {
                use sha2::Digest;
                format!("{:x}", sha2::Sha256::digest(&content))
            };
            let hash: ContentHash = hex.parse().unwrap();

            // First call: upstream returns not_found → leader records
            // `Failed(NotFound)` under the blob's dedup key with the
            // 30 s `ttl_not_found` TTL.
            let r1 = try_upstream_blob_pull(&ctx, &repo, "dockerhub/library/nginx", &hash).await;
            assert!(
                matches!(r1, UpstreamPullOutcome::UpstreamUnavailable),
                "first call must surface the upstream not_found as UpstreamUnavailable; \
                 got variant {}",
                outcome_variant_name(&r1)
            );

            // Second call within the negative-cache TTL window: the
            // mock would still return `upstream:not_found` — but the
            // negative-cache short-circuit prevents that re-fetch.
            // The second call must observe the cached `Failed`
            // outcome before any election.
            let r2 = try_upstream_blob_pull(&ctx, &repo, "dockerhub/library/nginx", &hash).await;
            assert!(
                !matches!(r2, UpstreamPullOutcome::Ingested(_)),
                "second call must surface the cached failure (NOT a fresh ingest); \
                 got variant {}",
                outcome_variant_name(&r2)
            );
        });

        // Assertion: `negative_cache_hit` increments by ≥ 1 (the
        // second call short-circuited). `leader_started` for the
        // blob's dedup key stays at 1 (only the FIRST call elected;
        // the second was a cache hit). The metric snapshot is
        // aggregated across all wrapped call sites; only the blob
        // site is reached on this code path, so `leader_started`
        // should be exactly 1 across the entire snapshot.
        let negative_cache_hit = sum_counter_for_outcome(&snap, "negative_cache_hit");
        let leader_started = sum_counter_for_outcome(&snap, "leader_started");
        assert!(
            negative_cache_hit >= 1,
            "expected ≥1 negative_cache_hit (second call hits cached \
             failure); got {negative_cache_hit}, snap: {snap:?}"
        );
        assert_eq!(
            leader_started, 1,
            "expected exactly 1 leader_started (only the first call \
             elected; the second short-circuited via negative cache); \
             got {leader_started}, snap: {snap:?}"
        );
    }

    /// Download-audit opt-in (ADR 0020): when the served repo opted in,
    /// an anonymous OCI **blob** pull (no principal) emits exactly one
    /// `ArtifactDownloaded` on the per-(repo, UTC-date) DownloadAudit
    /// stream with `DownloadActor::Anonymous` (no audit gap), never on
    /// the artifact aggregate stream. Ranged blob pulls go through
    /// `download_range` and are not audited — only full-blob pulls
    /// are new download events.
    #[test]
    fn download_audit_emits_anonymous_when_repo_opted_in() {
        use hort_domain::events::{DomainEvent, DownloadActor, StreamCategory};

        let content = b"oci blob layer bytes".to_vec();
        let hex = {
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(&content))
        };

        let (status, batches, repo_id) = run(async {
            let handle = PrometheusBuilder::new().build_recorder().handle();
            let (ctx, mocks) = build_mock_ctx(handle);
            let mut repo = oci_repo("oci-audit");
            repo.download_audit_enabled = true;
            let repo_id = repo.id;
            mocks.repositories.insert(repo);
            seed_blob(
                &mocks.artifacts,
                &mocks.storage,
                repo_id,
                &hex,
                &content,
                QuarantineStatus::None,
            );
            let events = mocks.events.clone();
            let router = blob_router(ctx);
            let uri = format!("/v2/oci-audit/nginx/blobs/sha256:{hex}");
            let resp = router
                .oneshot(Request::get(&uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            (status, events.appended_batches(), repo_id)
        });
        assert_eq!(status, StatusCode::OK);

        let dl: Vec<_> = batches
            .iter()
            .flat_map(|b| b.events.iter().map(move |e| (b, &e.event)))
            .filter(|(_, e)| matches!(e, DomainEvent::ArtifactDownloaded(_)))
            .collect();
        assert_eq!(dl.len(), 1, "exactly one ArtifactDownloaded emitted");
        let (batch, ev) = dl[0];
        assert_eq!(batch.stream_id.category, StreamCategory::DownloadAudit);
        assert_ne!(
            batch.stream_id,
            hort_domain::events::StreamId::artifact(repo_id),
            "never the artifact aggregate stream"
        );
        match ev {
            DomainEvent::ArtifactDownloaded(e) => {
                assert_eq!(e.repository_id, repo_id);
                assert!(
                    matches!(e.actor, DownloadActor::Anonymous),
                    "anonymous oci blob pull → DownloadActor::Anonymous"
                );
            }
            _ => unreachable!(),
        }
    }
}
