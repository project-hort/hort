//! Maven upstream pull-through orchestrator (ADR 0006, ADR 0033).
//!
//! Two-leg verified pull-through for a Maven-layout upstream:
//!
//! 1. Resolve the upstream mapping via [`UpstreamResolver`]. The requested
//!    Maven path maps **1:1** to the upstream Maven layout
//!    (`{group-path}/{artifact}/{version}/{filename}`), so the path is
//!    composed onto `mapping.upstream_url` verbatim.
//! 2. **Fetch the checksum sidecar, preferring strength:** `<path>.sha512` →
//!    `<path>.sha256` → `<path>.sha1` (the universal floor — ADR 0033). The
//!    first sidecar that fetches AND parses to a VALID digest of the matching
//!    shape wins; a 404, a transport failure, OR a malformed/empty/wrong-shape
//!    body on a stronger digest falls through to the next (weaker) digest.
//!    Parse the body to a bare lowercase hex digest (tolerating a trailing
//!    ` filename` suffix). The `.sha1` floor is the guarantee (design §8) — a
//!    corrupt `.sha512` must NOT block proxying an artifact that has a valid
//!    `.sha1`. **Only when all three are absent / unfetchable / unparseable →
//!    502** (unproxiable per ADR 0006 — NO soft-fail, NO unverified ingest).
//! 3. Build `VerifiedIngestRequest::UpstreamPublished{ upstream_checksum }`
//!    with the [`HashAlgorithm`] matching whichever sidecar won, fetch the
//!    artifact bytes, and ingest via [`IngestUseCase::ingest_verified`] —
//!    which rehashes the streamed bytes with the matching algorithm and
//!    compares (Conflict on mismatch). The CAS key is always the
//!    independently-computed SHA-256 regardless of which sidecar verified
//!    transfer.
//!
//! Both legs are coalesced through [`PullDedup`] (per-format-per-repo
//! [`DedupKey`]) so N parallel misses for the same artifact produce ≤ 1
//! upstream fetch + ≤ 1 CAS write.
//!
//! **Asymmetry with the trait-method floor (design §8/§15).** The
//! [`MavenFormatHandler`]'s `upstream_checksum_metadata_path` /
//! `parse_upstream_checksum` expose a SINGLE-path `.sha1` floor for the
//! DEFERRED generic prefetch-leaf consumer. The serve-path here does its own
//! `.sha512`→`.sha256`→`.sha1` upgrade and does NOT call those methods; the
//! asymmetry is intentional and both satisfy ADR 0006.
//!
//! `try_upstream_maven_pull` lives in this inbound-HTTP crate (NOT a use
//! case) — keeps the orchestration close to the route. Wire-mapping
//! ([`UpstreamPullError`] → HTTP status / body) is performed by
//! [`map_upstream_pull_error`], mirroring the Cargo / PyPI precedent.

use std::sync::Arc;

use axum::body::Body;
use axum::http::StatusCode;
use axum::response::Response;
use bytes::Bytes;
use tokio::io::AsyncRead;
use tokio_util::io::StreamReader;
use uuid::Uuid;

use hort_app::error::AppError;
use hort_app::pull_dedup::DedupKey;
use hort_app::use_cases::ingest_use_case::{RegisterExistingCasBlobRequest, VerifiedIngestRequest};
use hort_domain::entities::artifact::Artifact;
use hort_domain::entities::repository::Repository;
use hort_domain::error::DomainError;
use hort_domain::events::ApiActor;
use hort_domain::types::checksum::{HashAlgorithm, UpstreamPublishedChecksum};
use hort_domain::types::ArtifactCoords;
use hort_formats::maven::{parse_sidecar_hex, MavenFormatHandler};
use hort_http_core::context::AppContext;

/// The sidecar algorithms tried in **strength-preferring** order (ADR 0033):
/// `.sha512` (strongest) → `.sha256` → `.sha1` (the floor). The first
/// successful fetch wins; a 404 on a stronger digest falls through to the
/// next. The pair carries the `(HashAlgorithm, extension)` so the matching
/// algorithm threads into the `VerifiedIngestRequest` and the
/// `UpstreamPublishedChecksum::new` shape check.
const SIDECAR_PREFERENCE: [(HashAlgorithm, &str); 3] = [
    (HashAlgorithm::Sha512, "sha512"),
    (HashAlgorithm::Sha256, "sha256"),
    (HashAlgorithm::Sha1, "sha1"),
];

/// Discriminated failure modes for [`try_upstream_maven_pull`]. Wire mapping
/// (HTTP status + envelope body) is performed by the route handler; the
/// orchestrator itself only surfaces *what* went wrong, not *how to render
/// it*. Mirrors the Cargo / PyPI prior art adapted to the two-leg Maven
/// pipeline.
///
/// `ParseError(String)` / `IngestFailed(String)` / `Internal(String)` carry
/// the inner detail for tracing only — the wire-map renders a stable
/// client-facing envelope regardless of the specific message.
#[derive(Debug, thiserror::Error)]
pub(crate) enum UpstreamPullError {
    /// No upstream mapping configured for this repo. Wire to 404 — the
    /// artifact is genuinely unknown locally and the repo is not a usable
    /// proxy.
    #[error("no upstream mapping configured")]
    NoUpstreamMapping,

    /// Upstream returned 404 for the artifact body itself (the sidecar
    /// resolved, but the file is gone). Wire to 404 — the upstream simply
    /// doesn't have this file.
    #[error("upstream does not have this artifact")]
    NotFoundUpstream,

    /// None of `.sha512` / `.sha256` / `.sha1` yielded a USABLE checksum: each
    /// was either absent / unfetchable (404, transport) OR fetched-but-malformed
    /// (empty body, non-hex, wrong length). The serve-path falls through the
    /// preference list and only surfaces this once ALL THREE are exhausted with
    /// no valid digest — a corrupt stronger sidecar never blocks a valid floor
    /// (design §8). The artifact is **unproxiable** per ADR 0006 — there is no
    /// soft-fail / store-without-verify path. Wire to 502.
    #[error("no usable upstream checksum sidecar (sha512/sha256/sha1 all absent or malformed)")]
    NoChecksumSidecar,

    /// Upstream artifact-body fetch failed (5xx / network / timeout — NOT a
    /// 404, which is `NotFoundUpstream`). Wire to 502.
    #[error("upstream artifact fetch failed: {0}")]
    ArtifactFetchFailed(String),

    /// `IngestUseCase::ingest_verified` returned `Conflict` — the fetched
    /// bytes hashed differently from the sidecar digest (ADR 0006). The use
    /// case already emitted `ChecksumMismatch` and rolled back the CAS blob.
    /// Wire to 502 (`upstream-checksum-mismatch`).
    #[error("upstream checksum mismatch")]
    ChecksumMismatch,

    /// `IngestUseCase::ingest_verified` returned `CurationBlocked` — a
    /// curation rule matched the upstream artifact. The ingest use case
    /// already emitted the audit `tracing::info!`. Wire-map collapses this to
    /// 404 (byte-identical to a genuine miss) so a prober cannot distinguish
    /// a curation-blocked artifact from a non-existent one — the
    /// anti-enumeration contract and the Cargo / PyPI / OCI prior art.
    #[error("upstream artifact blocked by curation rule")]
    CurationBlocked,

    /// Any other ingest-time error — storage failure, event-store failure,
    /// repo lookup failure after ingest. Wire to 500.
    #[error("ingest failed: {0}")]
    IngestFailed(String),
}

/// On a local cache miss for a Maven artifact FILE, fetch it from the
/// configured upstream, verify it against the strongest available checksum
/// sidecar, and ingest into the local CAS.
///
/// `artifact_path` is the repo-relative Maven path (the `:repo_key` prefix
/// already stripped, the file-shape grammar already validated by
/// `parse_download_path` in the route handler). It maps 1:1 to the upstream
/// Maven layout. `coords` carries the GA:V identity + path the verified
/// ingest stores.
///
/// The `download` handler routes Proxy-repo file cache misses here.
/// Metadata / sidecar GETs are NOT proxied (they stay server-generated).
#[tracing::instrument(
    skip(ctx, coords),
    fields(repo_key = %repo.key, artifact_path),
)]
pub(crate) async fn try_upstream_maven_pull(
    ctx: &Arc<AppContext>,
    repo: &Repository,
    coords: &ArtifactCoords,
    artifact_path: &str,
) -> Result<Artifact, UpstreamPullError> {
    // 1. Resolve upstream mapping. Maven is single-upstream per repo today
    //    (no path-prefix routing); the framework call passes `""`.
    let Some((mapping, _stripped)) = ctx.upstream_resolver.resolve(repo.id, "") else {
        tracing::warn!("Maven repository has no upstream mapping configured");
        return Err(UpstreamPullError::NoUpstreamMapping);
    };

    // 2. Fetch the checksum sidecar, preferring strength. The first sidecar
    //    that fetches AND parses to a VALID digest wins; a not-found, transport
    //    failure, OR a malformed body on a stronger digest falls through to the
    //    next (weaker) digest. Shape validation happens inside the loop so a
    //    corrupt `.sha512` never blocks a valid `.sha1` floor (design §8). All
    //    three exhausted with no valid digest → NoChecksumSidecar (502).
    let (algorithm, upstream_checksum) =
        fetch_strongest_sidecar(ctx, repo, &mapping, artifact_path).await?;

    // 3. Stream the artifact body and ingest_verified. The use case rehashes
    //    while streaming with the matching algorithm and returns Conflict on
    //    a mismatch — the security primitive against upstream tampering
    //    (ADR 0006). Coalesce the fetch + ingest so N parallel callers for
    //    the same artifact produce ≤ 1 upstream fetch + ≤ 1 CAS write. The
    //    dedup key is the verified upstream digest (pre-known per ADR 0006),
    //    so different repos pointing at the same upstream share one window.
    let dedup_alg = algorithm_token(algorithm);
    let blob_dedup_key = DedupKey::blob_by_hash(dedup_alg, upstream_checksum.hex());
    let blob_proxy = ctx.upstream_proxy.clone();
    let blob_mapping = mapping.clone();
    let blob_path = artifact_path.to_string();
    let blob_ingest = ctx.ingest_use_case.clone();
    let blob_repo_id = repo.id;
    let blob_trust_publish_time = mapping.trust_upstream_publish_time;
    let blob_upstream_url = mapping.upstream_url.clone();
    let follower_upstream_url = blob_upstream_url.clone();
    // Extract the filename from the Maven layout path, then delegate to the
    // shared extension→content-type map (the hosted PUT path's
    // `content_type_for`) so a proxied artifact stores the same content-type a
    // directly-deployed one would.
    let content_type =
        crate::content_type_for(artifact_path.rsplit('/').next().unwrap_or(artifact_path));
    let follower_content_type = content_type.clone();
    let follower_coords = coords.clone();
    let blob_coords = coords.clone();
    let blob_upstream_checksum = upstream_checksum;
    let coalesce_blob_result = ctx
        .pull_dedup
        .coalesce_blob(blob_dedup_key, move || async move {
            let fetch = blob_proxy
                .fetch_artifact(blob_mapping, blob_path)
                .await
                .map_err(AppError::from)?;
            // The artifact response's `Last-Modified` ≈ upstream publish time
            // for an immutable Maven release; best-effort, absent → None.
            let upstream_published_at = fetch.last_modified;
            let reader: Box<dyn AsyncRead + Send + Unpin> =
                Box::new(StreamReader::new(fetch.stream));
            let request = VerifiedIngestRequest::UpstreamPublished {
                repository_id: blob_repo_id,
                coords: blob_coords,
                content_type,
                actor: ApiActor {
                    user_id: Uuid::nil(),
                },
                payload_metadata: serde_json::json!({
                    "source": "maven_upstream_pull",
                    "upstream_url": blob_upstream_url,
                }),
                upstream_checksum: blob_upstream_checksum,
                upstream_published_at,
                trust_upstream_publish_time: blob_trust_publish_time,
            };
            let outcome = blob_ingest
                .ingest_verified(request, reader, &MavenFormatHandler)
                .await?;
            Ok(outcome.artifact.sha256_checksum)
        })
        .await;

    let content_hash = match coalesce_blob_result {
        Ok(h) => h,
        // Leader-side typed discriminators preserve the wire-mapping;
        // follower-side errors arrive wrapped as `AppError::External` and
        // route to `IngestFailed` (leader-only discrimination contract).
        Err(AppError::Domain(DomainError::Conflict(msg))) => {
            tracing::warn!(conflict = %msg, "Maven upstream checksum mismatch");
            return Err(UpstreamPullError::ChecksumMismatch);
        }
        Err(AppError::Domain(DomainError::CurationBlocked { .. })) => {
            tracing::warn!("Maven upstream artifact blocked by curation rule");
            return Err(UpstreamPullError::CurationBlocked);
        }
        Err(e) => {
            // `fetch_artifact` 404 → NotFoundUpstream; other transport
            // failures → ArtifactFetchFailed (502); anything else →
            // IngestFailed (500). The upstream adapter prefixes transport
            // errors with "upstream:" (see `MockUpstreamProxy::fetch_artifact`
            // and the production `UpstreamHttpAdapter`); the not-found
            // sentinel is `upstream:not_found:`.
            let msg = e.to_string();
            if is_upstream_not_found(&msg) {
                tracing::warn!(error = %e, "Maven upstream artifact not found");
                return Err(UpstreamPullError::NotFoundUpstream);
            }
            if is_upstream_transport(&msg) {
                tracing::warn!(error = %e, "Maven upstream artifact fetch failed");
                return Err(UpstreamPullError::ArtifactFetchFailed(msg));
            }
            tracing::warn!(error = %e, "Maven upstream ingest failed");
            return Err(UpstreamPullError::IngestFailed(msg));
        }
    };

    // Post-coalesce read: both leader and follower re-resolve the artifact
    // row by content hash. `blob_by_hash` is cross-repo, so a follower whose
    // leader ingested into a DIFFERENT repo has no row in `repo.id` → it
    // idempotently registers its OWN per-repo row (content already
    // CAS-present + verified; no re-fetch, no re-`storage.put`).
    let artifact = match ctx
        .artifact_use_case
        .find_in_repo_by_hash(repo.id, &content_hash)
        .await
        .map_err(|e| UpstreamPullError::IngestFailed(e.to_string()))?
    {
        Some(a) => a,
        None => {
            ctx.ingest_use_case
                .register_existing_cas_blob(
                    RegisterExistingCasBlobRequest {
                        repository_id: repo.id,
                        coords: follower_coords,
                        content_type: follower_content_type,
                        actor: ApiActor {
                            user_id: Uuid::nil(),
                        },
                        payload_metadata: serde_json::json!({
                            "source": "maven_upstream_pull",
                            "upstream_url": follower_upstream_url,
                        }),
                        content_hash: content_hash.clone(),
                        // Upstream pull is not a seed-import cutover;
                        // quarantine is policy-driven through the primary
                        // `ingest_verified` path.
                        seed_import_quarantine_anchor: None,
                    },
                    &MavenFormatHandler,
                )
                .await
                .map_err(|e| UpstreamPullError::IngestFailed(e.to_string()))?
                .artifact
        }
    };

    tracing::info!(
        artifact_id = %artifact.id,
        algorithm = algorithm_token(algorithm),
        "Maven upstream pull-through completed; ChecksumVerified emitted"
    );
    Ok(artifact)
}

/// Fetch the strongest available checksum sidecar for `artifact_path`,
/// trying `.sha512` → `.sha256` → `.sha1` in order. The first sidecar that
/// fetches AND parses to a VALID digest of the matching shape wins.
///
/// The `.sha1` floor is the guarantee (design §8 / ADR 0033): the
/// opportunistic-upgrade model uses the strongest sidecar that yields a valid
/// checksum, but the floor must always be usable. Therefore a sidecar that is
/// absent / unfetchable (404, transport) OR fetched-but-malformed (empty body,
/// non-hex, wrong length) falls through to the next (weaker) digest — a corrupt
/// `.sha512` must NOT block proxying an artifact that has a valid `.sha1`.
/// There is no distinct threat from this fall-through: an attacker who can
/// corrupt the upstream's `.sha512` over the TLS channel can equally serve a
/// matching-malicious `.sha512`, so forcing a downgrade is not a new attack.
///
/// Returns `(HashAlgorithm, UpstreamPublishedChecksum)` (already shape-checked)
/// on the first hit. Returns [`UpstreamPullError::NoChecksumSidecar`] only when
/// ALL THREE are exhausted with no valid digest — the artifact is unproxiable
/// per ADR 0006 (no soft-fail). A genuine checksum *mismatch* (artifact bytes ≠
/// a valid sidecar digest) is detected later, by `ingest_verified`, and stays
/// its own [`UpstreamPullError::ChecksumMismatch`] (502) path.
async fn fetch_strongest_sidecar(
    ctx: &Arc<AppContext>,
    repo: &Repository,
    mapping: &hort_domain::ports::repository_upstream_mapping_repository::RepositoryUpstreamMapping,
    artifact_path: &str,
) -> Result<(HashAlgorithm, UpstreamPublishedChecksum), UpstreamPullError> {
    for (algorithm, ext) in SIDECAR_PREFERENCE {
        let sidecar_path = format!("{artifact_path}.{ext}");
        match fetch_sidecar_body(ctx, repo, mapping, &sidecar_path).await {
            // Body fetched — parse the bare hex token and validate its shape
            // for this algorithm. A malformed body (empty / non-hex / wrong
            // length) is treated like an absent sidecar: fall through to the
            // next (weaker) digest rather than short-circuit. The floor must
            // always be reachable (design §8).
            Ok(body) => match parse_and_validate(algorithm, &body) {
                Ok(checksum) => {
                    tracing::debug!(algorithm = ext, "Maven upstream sidecar resolved");
                    return Ok((algorithm, checksum));
                }
                Err(reason) => {
                    // No bytes echoed — only the algorithm + a classified
                    // reason. A present-but-broken stronger sidecar must not
                    // deny a valid weaker one.
                    tracing::warn!(
                        algorithm = ext,
                        reason = %reason,
                        "Maven upstream sidecar malformed; trying weaker digest"
                    );
                }
            },
            // Not-found (or any fetch failure) on this digest → fall through
            // to the next (weaker) digest. The floor `.sha1` exhausting the
            // loop is the genuine "unproxiable" case.
            Err(SidecarFetchError::Unavailable(msg)) => {
                tracing::debug!(
                    algorithm = ext,
                    cause = %msg,
                    "Maven upstream sidecar unavailable; trying weaker digest"
                );
            }
        }
    }
    tracing::warn!(
        artifact_path,
        "Maven upstream publishes no usable sha512/sha256/sha1 sidecar — unproxiable (ADR 0006)"
    );
    Err(UpstreamPullError::NoChecksumSidecar)
}

/// Parse a fetched sidecar body into a shape-validated
/// [`UpstreamPublishedChecksum`] for `algorithm`, or return a short
/// `UpstreamErrorKind`-classified reason string (NO raw bytes) describing why
/// it is unusable. Both the empty/whitespace case (via [`parse_sidecar_hex`])
/// and the wrong-shape case (via [`UpstreamPublishedChecksum::new`]) classify
/// as `upstream-metadata-malformed` so the caller can uniformly fall through.
fn parse_and_validate(
    algorithm: HashAlgorithm,
    body: &str,
) -> Result<UpstreamPublishedChecksum, String> {
    let hex = parse_sidecar_hex(body)
        .map_err(|_| "upstream-metadata-malformed: empty/no digest token".to_string())?;
    UpstreamPublishedChecksum::new(algorithm, hex)
        .map_err(|_| "upstream-metadata-malformed: digest failed shape validation".to_string())
}

/// A single sidecar fetch failed — every failure mode (404, 5xx, network)
/// collapses to one variant because the negotiation treats them all as "this
/// digest is unavailable, try the next". The floor exhausting the loop is the
/// only place a fetch failure becomes terminal (→ `NoChecksumSidecar`).
enum SidecarFetchError {
    Unavailable(String),
}

/// Fetch and materialise one sidecar body (a tiny one-line digest) through
/// `PullDedup::coalesce_metadata`, returning the raw bytes as a `String`.
///
/// The sidecar is fetched via [`UpstreamProxy::fetch_metadata`] (the
/// metadata leg) with a per-format-per-repo [`DedupKey`] so N parallel misses
/// for the same sidecar produce ≤ 1 upstream round-trip. The body is
/// recovered via the [`IdentityProjector`] (a sidecar has no per-format
/// projection — it is a bare digest line) and the tempfile cleaned up.
async fn fetch_sidecar_body(
    ctx: &Arc<AppContext>,
    repo: &Repository,
    mapping: &hort_domain::ports::repository_upstream_mapping_repository::RepositoryUpstreamMapping,
    sidecar_path: &str,
) -> Result<String, SidecarFetchError> {
    let dedup_key = DedupKey::metadata("maven", repo.id, sidecar_path);
    let proxy = ctx.upstream_proxy.clone();
    let mapping = mapping.clone();
    let path = sidecar_path.to_string();
    let bytes = ctx
        .pull_dedup
        .coalesce_metadata(dedup_key, move || async move {
            let outcome = proxy
                .fetch_metadata(mapping, path, Vec::new())
                .await
                .map_err(AppError::from)?;
            let handle = outcome.cache_handle.as_ref().ok_or_else(|| {
                AppError::from(DomainError::Invariant(
                    "maven sidecar fetch_metadata returned no cache_handle".to_string(),
                ))
            })?;
            // A sidecar is a bare digest line — no per-format projection.
            let body = hort_app::project::project_cached(
                handle,
                hort_domain::ports::upstream_proxy::IdentityProjector,
            )
            .await
            .map_err(AppError::from)?;
            if let Err(e) = tokio::fs::remove_file(&handle.path).await {
                tracing::debug!(
                    path = %handle.path.display(),
                    error = %e,
                    "maven sidecar tempfile cleanup failed (non-fatal)"
                );
            }
            Ok(Bytes::from(body))
        })
        .await
        .map_err(|e| SidecarFetchError::Unavailable(e.to_string()))?;

    // The sidecar body is tiny (one digest line); a lossy-utf8 view is fine —
    // a non-UTF-8 sidecar parses to no valid hex token and fails downstream
    // as a ParseError, never a silent skip.
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// The lowercase metric/dedup token for a [`HashAlgorithm`].
fn algorithm_token(algorithm: HashAlgorithm) -> &'static str {
    match algorithm {
        HashAlgorithm::Sha1 => "sha1",
        HashAlgorithm::Sha256 => "sha256",
        HashAlgorithm::Sha512 => "sha512",
    }
}

/// Whether a rendered upstream error string is the not-found sentinel.
/// The production adapter and `MockUpstreamProxy` both emit
/// `upstream:not_found:...` for a 404.
fn is_upstream_not_found(msg: &str) -> bool {
    msg.contains("upstream:not_found")
}

/// Whether a rendered upstream error string is a (non-404) transport failure
/// (5xx / network / timeout). The adapter prefixes such errors with
/// `upstream:` / `upstream `.
fn is_upstream_transport(msg: &str) -> bool {
    msg.contains("upstream:") || msg.contains("upstream ")
}

/// Wire-mapping for [`UpstreamPullError`] used by the `download` handler's
/// Proxy-cache-miss branch.
///
/// | Variant | Status | `X-Hort-Reason` |
/// |---|---|---|
/// | `NoUpstreamMapping` / `NotFoundUpstream` / `CurationBlocked` | 404 | — |
/// | `NoChecksumSidecar` | 502 | `upstream-no-checksum-sidecar` |
/// | `ChecksumMismatch` | 502 | `upstream-checksum-mismatch` |
/// | `ArtifactFetchFailed` | 502 | `upstream-artifact-fetch-failed` |
/// | `IngestFailed` | 500 | — |
///
/// Notes:
/// - `NoChecksumSidecar` is the ADR 0006 "unproxiable" 502 (all of
///   `.sha512`/`.sha256`/`.sha1` absent OR malformed after fall-through — no
///   soft-fail, never a store-without-verify).
/// - `CurationBlocked` collapses to the SAME 404 envelope as a genuine miss
///   (anti-enumeration — the Cargo / PyPI / OCI prior art). The curation
///   event is already emitted by `IngestUseCase`.
/// - `IngestFailed` returns a short stable string — never the inner message —
///   to match the `hort_http_core::error` sanitisation contract.
pub(crate) fn map_upstream_pull_error(e: &UpstreamPullError) -> Response {
    match e {
        UpstreamPullError::NoUpstreamMapping
        | UpstreamPullError::NotFoundUpstream
        | UpstreamPullError::CurationBlocked => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::json!({"error": "artifact not found"}).to_string(),
            ))
            .unwrap(),
        UpstreamPullError::NoChecksumSidecar => Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .header("Content-Type", "application/json")
            .header("X-Hort-Reason", "upstream-no-checksum-sidecar")
            .body(Body::from(
                serde_json::json!({"error": "upstream publishes no usable checksum"}).to_string(),
            ))
            .unwrap(),
        UpstreamPullError::ChecksumMismatch => Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .header("Content-Type", "application/json")
            .header("X-Hort-Reason", "upstream-checksum-mismatch")
            .body(Body::from(
                serde_json::json!({"error": "upstream tampering detected"}).to_string(),
            ))
            .unwrap(),
        UpstreamPullError::ArtifactFetchFailed(_) => Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .header("Content-Type", "application/json")
            .header("X-Hort-Reason", "upstream-artifact-fetch-failed")
            .body(Body::from(
                serde_json::json!({"error": "upstream unavailable"}).to_string(),
            ))
            .unwrap(),
        UpstreamPullError::IngestFailed(_) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::json!({"error": "ingest failed"}).to_string(),
            ))
            .unwrap(),
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use uuid::Uuid;

    use hort_app::use_cases::test_support::sample_repository;
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::repository::{Repository, RepositoryFormat, RepositoryType};
    use hort_domain::ports::format_handler::FormatHandler;
    use hort_domain::ports::repository_upstream_mapping_repository::{
        RepositoryUpstreamMapping, UpstreamAuth,
    };
    use hort_http_core::test_support::{build_mock_ctx, MockPorts};

    use super::*;

    fn handle() -> metrics_exporter_prometheus::PrometheusHandle {
        PrometheusBuilder::new().build_recorder().handle()
    }

    fn sha1_hex(content: &[u8]) -> String {
        use sha1::{Digest, Sha1};
        format!("{:x}", Sha1::digest(content))
    }

    fn sha256_hex(content: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        format!("{:x}", Sha256::digest(content))
    }

    fn sha512_hex(content: &[u8]) -> String {
        use sha2::{Digest, Sha512};
        format!("{:x}", Sha512::digest(content))
    }

    fn proxy_maven_repo(key: &str) -> Repository {
        let mut r = sample_repository();
        r.key = key.into();
        r.format = RepositoryFormat::Maven;
        r.repo_type = RepositoryType::Proxy;
        r.upstream_url = Some("https://repo1.maven.org/maven2".into());
        r
    }

    fn seed_mapping(mocks: &MockPorts, repo_id: Uuid) -> Uuid {
        let id = Uuid::new_v4();
        let now = Utc::now();
        mocks.upstream_resolver.insert(RepositoryUpstreamMapping {
            id,
            repository_id: repo_id,
            path_prefix: "".into(),
            upstream_url: "https://repo1.maven.org/maven2".into(),
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
        id
    }

    const ARTIFACT_PATH: &str = "com/example/foo/1.0/foo-1.0.jar";

    fn coords_for(path: &str) -> ArtifactCoords {
        MavenFormatHandler.parse_download_path(path).unwrap()
    }

    // ---- Branch: no mapping -------------------------------------------------

    #[tokio::test]
    async fn no_upstream_mapping_returns_no_upstream_mapping() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = proxy_maven_repo("maven-mirror");
        mocks.repositories.insert(repo.clone());

        let err = try_upstream_maven_pull(&ctx, &repo, &coords_for(ARTIFACT_PATH), ARTIFACT_PATH)
            .await
            .unwrap_err();

        assert!(
            matches!(err, UpstreamPullError::NoUpstreamMapping),
            "expected NoUpstreamMapping, got {err:?}"
        );
    }

    // ---- Branch: sha1 floor verifies (proves the floor) ---------------------

    #[tokio::test]
    async fn only_sha1_present_verifies_via_floor() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = proxy_maven_repo("maven-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id);

        let body = b"the actual jar body".to_vec();
        // Only the .sha1 sidecar present — .sha512 and .sha256 are absent.
        mocks.upstream_proxy.insert_metadata(
            "",
            &format!("{ARTIFACT_PATH}.sha1"),
            sha1_hex(&body).into_bytes(),
        );
        mocks
            .upstream_proxy
            .insert_artifact("", ARTIFACT_PATH, body.clone());

        let artifact =
            try_upstream_maven_pull(&ctx, &repo, &coords_for(ARTIFACT_PATH), ARTIFACT_PATH)
                .await
                .expect("sha1 floor must verify + ingest");

        assert_eq!(artifact.name, "com.example:foo");
        assert_eq!(artifact.version.as_deref(), Some("1.0"));
        assert_eq!(artifact.size_bytes as usize, body.len());
        // The CAS key is always SHA-256 regardless of the verifying sidecar.
        assert_eq!(artifact.sha256_checksum.as_ref(), sha256_hex(&body));
    }

    // ---- Branch: sha256 present verifies ------------------------------------

    #[tokio::test]
    async fn sha256_present_verifies() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = proxy_maven_repo("maven-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id);

        let body = b"the actual jar body".to_vec();
        // .sha512 absent → falls through to .sha256.
        mocks.upstream_proxy.insert_metadata(
            "",
            &format!("{ARTIFACT_PATH}.sha256"),
            sha256_hex(&body).into_bytes(),
        );
        mocks
            .upstream_proxy
            .insert_artifact("", ARTIFACT_PATH, body.clone());

        let artifact =
            try_upstream_maven_pull(&ctx, &repo, &coords_for(ARTIFACT_PATH), ARTIFACT_PATH)
                .await
                .expect("sha256 sidecar must verify + ingest");

        assert_eq!(artifact.sha256_checksum.as_ref(), sha256_hex(&body));
    }

    // ---- Branch: sha512 preferred over sha1 (proves upgrade preference) -----

    #[tokio::test]
    async fn sha512_preferred_over_weaker_digests() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = proxy_maven_repo("maven-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id);

        let body = b"the actual jar body".to_vec();
        // All three present. The .sha1 and .sha256 carry a LYING digest; only
        // .sha512 is correct. A successful verify proves .sha512 was the one
        // chosen (the weaker digests would have produced a mismatch).
        mocks.upstream_proxy.insert_metadata(
            "",
            &format!("{ARTIFACT_PATH}.sha512"),
            sha512_hex(&body).into_bytes(),
        );
        mocks.upstream_proxy.insert_metadata(
            "",
            &format!("{ARTIFACT_PATH}.sha256"),
            sha256_hex(b"a totally different payload").into_bytes(),
        );
        mocks.upstream_proxy.insert_metadata(
            "",
            &format!("{ARTIFACT_PATH}.sha1"),
            sha1_hex(b"yet another payload").into_bytes(),
        );
        mocks
            .upstream_proxy
            .insert_artifact("", ARTIFACT_PATH, body.clone());

        let artifact =
            try_upstream_maven_pull(&ctx, &repo, &coords_for(ARTIFACT_PATH), ARTIFACT_PATH)
                .await
                .expect("sha512 must be preferred and verify");

        assert_eq!(artifact.sha256_checksum.as_ref(), sha256_hex(&body));
    }

    // ---- Branch: checksum mismatch → 502 ------------------------------------

    #[tokio::test]
    async fn checksum_mismatch_returns_checksum_mismatch() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = proxy_maven_repo("maven-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id);

        let actual = b"actual bytes".to_vec();
        // The sidecar advertises the digest of DIFFERENT bytes → the use
        // case rehashes the streamed bytes and returns Conflict.
        mocks.upstream_proxy.insert_metadata(
            "",
            &format!("{ARTIFACT_PATH}.sha256"),
            sha256_hex(b"different bytes").into_bytes(),
        );
        mocks
            .upstream_proxy
            .insert_artifact("", ARTIFACT_PATH, actual);

        let err = try_upstream_maven_pull(&ctx, &repo, &coords_for(ARTIFACT_PATH), ARTIFACT_PATH)
            .await
            .unwrap_err();

        assert!(
            matches!(err, UpstreamPullError::ChecksumMismatch),
            "expected ChecksumMismatch, got {err:?}"
        );
    }

    // ---- Branch: all three sidecars absent → 502 (unproxiable) --------------

    #[tokio::test]
    async fn all_sidecars_absent_returns_no_checksum_sidecar() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = proxy_maven_repo("maven-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id);

        // The artifact body is present but NO sidecar is — unproxiable per
        // ADR 0006 (no soft-fail, no unverified ingest).
        mocks
            .upstream_proxy
            .insert_artifact("", ARTIFACT_PATH, b"unverifiable".to_vec());

        let err = try_upstream_maven_pull(&ctx, &repo, &coords_for(ARTIFACT_PATH), ARTIFACT_PATH)
            .await
            .unwrap_err();

        assert!(
            matches!(err, UpstreamPullError::NoChecksumSidecar),
            "expected NoChecksumSidecar, got {err:?}"
        );
    }

    // ---- Branch: malformed stronger sidecar falls through to a valid floor --
    //
    // The opportunistic-upgrade model (design §8 / ADR 0033): a corrupt
    // `.sha512` must NOT block proxying an artifact that has a valid `.sha1`
    // floor. The strongest sidecar that yields a VALID checksum wins; the floor
    // is the guarantee. (Replaces the prior "present-but-malformed → 502"
    // short-circuit.)

    #[tokio::test]
    async fn malformed_sha512_falls_through_to_valid_sha1_floor() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = proxy_maven_repo("maven-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id);

        let body = b"the actual jar body".to_vec();
        // .sha512 present but its body is empty (whitespace only) — malformed.
        mocks.upstream_proxy.insert_metadata(
            "",
            &format!("{ARTIFACT_PATH}.sha512"),
            b"   \n".to_vec(),
        );
        // .sha256 also present but NON-HEX (wrong shape) — malformed.
        mocks.upstream_proxy.insert_metadata(
            "",
            &format!("{ARTIFACT_PATH}.sha256"),
            b"not-a-valid-digest".to_vec(),
        );
        // .sha1 is valid → the floor wins and the artifact verifies + ingests.
        mocks.upstream_proxy.insert_metadata(
            "",
            &format!("{ARTIFACT_PATH}.sha1"),
            sha1_hex(&body).into_bytes(),
        );
        mocks
            .upstream_proxy
            .insert_artifact("", ARTIFACT_PATH, body.clone());

        let artifact =
            try_upstream_maven_pull(&ctx, &repo, &coords_for(ARTIFACT_PATH), ARTIFACT_PATH)
                .await
                .expect("malformed stronger sidecars must fall through to the valid sha1 floor");

        // The CAS key is always SHA-256 regardless of the verifying sidecar.
        assert_eq!(artifact.sha256_checksum.as_ref(), sha256_hex(&body));
    }

    // ---- Branch: ALL present sidecars malformed → 502 (no usable checksum) ---

    #[tokio::test]
    async fn all_present_sidecars_malformed_returns_no_checksum_sidecar() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = proxy_maven_repo("maven-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id);

        // Every sidecar fetches but none parses to a valid digest of its shape:
        // .sha512 empty, .sha256 non-hex, .sha1 wrong length. The loop exhausts
        // with no valid checksum → NoChecksumSidecar (502), unproxiable.
        mocks.upstream_proxy.insert_metadata(
            "",
            &format!("{ARTIFACT_PATH}.sha512"),
            b"   \n".to_vec(),
        );
        mocks.upstream_proxy.insert_metadata(
            "",
            &format!("{ARTIFACT_PATH}.sha256"),
            b"not-a-valid-digest".to_vec(),
        );
        mocks.upstream_proxy.insert_metadata(
            "",
            &format!("{ARTIFACT_PATH}.sha1"),
            b"deadbeef".to_vec(), // 8 hex chars — sha1 requires 40.
        );
        mocks
            .upstream_proxy
            .insert_artifact("", ARTIFACT_PATH, b"body".to_vec());

        let err = try_upstream_maven_pull(&ctx, &repo, &coords_for(ARTIFACT_PATH), ARTIFACT_PATH)
            .await
            .unwrap_err();

        assert!(
            matches!(err, UpstreamPullError::NoChecksumSidecar),
            "expected NoChecksumSidecar, got {err:?}"
        );
    }

    // ---- Branch: upstream artifact 404 → NotFoundUpstream -------------------

    #[tokio::test]
    async fn upstream_artifact_404_returns_not_found_upstream() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = proxy_maven_repo("maven-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id);

        let body = b"the jar body".to_vec();
        // Sidecar resolves but the artifact body is NOT seeded → fetch_artifact
        // returns the not-found sentinel.
        mocks.upstream_proxy.insert_metadata(
            "",
            &format!("{ARTIFACT_PATH}.sha256"),
            sha256_hex(&body).into_bytes(),
        );

        let err = try_upstream_maven_pull(&ctx, &repo, &coords_for(ARTIFACT_PATH), ARTIFACT_PATH)
            .await
            .unwrap_err();

        assert!(
            matches!(err, UpstreamPullError::NotFoundUpstream),
            "expected NotFoundUpstream, got {err:?}"
        );
    }

    // ---- Branch: tolerates a trailing-filename sidecar shape ----------------

    #[tokio::test]
    async fn sidecar_with_trailing_filename_verifies() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = proxy_maven_repo("maven-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id);

        let body = b"the actual jar body".to_vec();
        // GNU coreutils shape: `<hex>  <filename>`.
        let sidecar = format!("{}  foo-1.0.jar", sha256_hex(&body));
        mocks.upstream_proxy.insert_metadata(
            "",
            &format!("{ARTIFACT_PATH}.sha256"),
            sidecar.into_bytes(),
        );
        mocks
            .upstream_proxy
            .insert_artifact("", ARTIFACT_PATH, body.clone());

        let artifact =
            try_upstream_maven_pull(&ctx, &repo, &coords_for(ARTIFACT_PATH), ARTIFACT_PATH)
                .await
                .expect("trailing-filename sidecar must verify");
        assert_eq!(artifact.sha256_checksum.as_ref(), sha256_hex(&body));
    }

    // ---- Wire mapping -------------------------------------------------------

    #[test]
    fn wire_map_status_codes() {
        let cases = [
            (UpstreamPullError::NoUpstreamMapping, StatusCode::NOT_FOUND),
            (UpstreamPullError::NotFoundUpstream, StatusCode::NOT_FOUND),
            (UpstreamPullError::CurationBlocked, StatusCode::NOT_FOUND),
            (
                UpstreamPullError::NoChecksumSidecar,
                StatusCode::BAD_GATEWAY,
            ),
            (UpstreamPullError::ChecksumMismatch, StatusCode::BAD_GATEWAY),
            (
                UpstreamPullError::ArtifactFetchFailed("x".into()),
                StatusCode::BAD_GATEWAY,
            ),
            (
                UpstreamPullError::IngestFailed("x".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ];
        for (err, expected) in cases {
            let resp = map_upstream_pull_error(&err);
            assert_eq!(resp.status(), expected, "wrong status for {err:?}");
        }
    }

    #[test]
    fn wire_map_no_checksum_sidecar_reason_header() {
        let resp = map_upstream_pull_error(&UpstreamPullError::NoChecksumSidecar);
        assert_eq!(
            resp.headers().get("X-Hort-Reason").unwrap(),
            "upstream-no-checksum-sidecar"
        );
    }
}
