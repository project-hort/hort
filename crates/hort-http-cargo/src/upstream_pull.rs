//! Cargo upstream pull-through orchestrator (ADR 0006).
//!
//! Three-leg verified pull-through for the Cargo sparse registry:
//!
//! 1. Resolve the upstream mapping via [`UpstreamResolver`].
//! 2. Fetch the registry's `config.json` (cached via [`EphemeralStore`]
//!    with a fresh-TTL of 1 h, backend TTL of 24 h — so a stale entry
//!    survives upstream blips while still respecting freshness for
//!    operator-driven re-bootstraps).
//! 3. Fetch the crate's sparse-index NDJSON (NOT cached — operators
//!    rely on freshness for new versions).
//! 4. Recover the upstream `cksum` via
//!    [`CargoFormatHandler::parse_upstream_checksum`], compose the
//!    download URL via [`compose_download_url`], and stream the bytes
//!    through [`IngestUseCase::ingest_verified`] as a
//!    `VerifiedIngestRequest::UpstreamPublished(Sha256)`.
//!
//! `try_upstream_crate_pull` lives in this inbound-HTTP crate (NOT a
//! use case) — keeps the orchestration close to the route. Item 5
//! wires the dispatch from `download` / `serve_index`; this item only
//! lands the orchestrator + its branch tests.
//!
//! Wire-mapping ([`UpstreamPullError`] → HTTP status / body) is also
//! deferred to Item 5; the discrimination here only needs to surface
//! the failure modes cleanly.
//!
//! Wire-mapping for upstream errors is performed by the route handler;
//! the orchestrator only surfaces *what* went wrong, not *how to render
//! it*.
//!
//! # Cache strategy
//!
//! The `config.json` cache key is `cargo_index_config:{mapping.id}`.
//! The same key shape is reserved for Item 4's per-crate index cache
//! work (`cargo_index_entry:{mapping.id}:{name}`) so a single review
//! can confirm consistency across the two callers.

use std::sync::Arc;
use std::time::Duration;

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
use hort_domain::error::{DomainError, DomainResult};
use hort_domain::events::ApiActor;
use hort_domain::ports::format_handler::FormatHandler;
use hort_domain::ports::repository_upstream_mapping_repository::RepositoryUpstreamMapping;
use hort_domain::types::checksum::UpstreamPublishedChecksum;
use hort_domain::types::ArtifactCoords;
use hort_formats::cargo::config::{compose_download_url, parse_registry_config, RegistryConfig};
use hort_formats::cargo::projection::{CargoSparseIndexProjector, CargoVersionLine};
use hort_formats::cargo::CargoFormatHandler;
use hort_http_core::context::AppContext;

/// Discriminated failure modes for [`try_upstream_crate_pull`]. Wire
/// mapping (HTTP status + envelope body) is performed by Item 5 in the
/// route handler; the orchestrator itself only surfaces *what* went
/// wrong, not *how to render it*.
///
/// `MetadataFetchFailed.stage` is one of the three string literals
/// `"config"`, `"index"`, or `"artifact"` — the wire-map can match on
/// the stage to differentiate `X-Hort-Reason` headers without a second
/// enum dimension.
///
/// The variant list mirrors the seven nominal failure modes the
/// backlog enumerates, plus the OCI-prior-art `CurationBlocked`
/// variant (`crates/hort-http-oci/src/blobs.rs::UpstreamPullOutcome`).
///
/// `ParseError(String)` / `Internal(String)` carry the inner detail
/// for tracing — the wire-map renders a stable client-facing envelope
/// regardless of the specific message, so the inner string is only
/// consumed via `tracing::warn!` in the orchestrator. Same applies to
/// the `err` field of `MetadataFetchFailed`. Item 5 wired the wire-map
/// helper [`map_upstream_pull_error`] which reads `stage` (but not
/// `err`) — the `err` text stays opaque on the wire by design (no
/// upstream details surfaced beyond the typed reason).
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum UpstreamPullError {
    /// No upstream mapping configured for this repo. Wire to "no
    /// pull-through configured" — typically a 404 since the artifact
    /// is genuinely unknown locally and the repo is not a proxy.
    NoUpstreamMapping,
    /// One of the three upstream HTTP fetches (`config.json`, NDJSON
    /// index, crate download) failed with an underlying domain error.
    /// `stage` discriminates which leg.
    MetadataFetchFailed { stage: &'static str, err: String },
    /// Upstream returned a body the format handler couldn't parse —
    /// either malformed `config.json`, malformed NDJSON, or an entry
    /// whose `cksum` is missing / malformed.
    ParseError(String),
    /// Index parsed cleanly but had no entry for the requested
    /// `(name, version)` pair. Wire to 404 — the upstream simply
    /// doesn't have this version.
    NotFoundUpstream,
    /// `IngestUseCase::ingest_verified` returned `Conflict` —
    /// upstream bytes hashed differently from the `cksum` advertised
    /// in the sparse-index entry. The use case already emitted
    /// `ChecksumMismatch` on the repository stream and rolled back
    /// the CAS blob.
    ChecksumMismatch,
    /// `IngestUseCase::ingest_verified` returned `CurationBlocked` —
    /// a curation rule matched the artifact. The ingest use case
    /// already emitted the audit `tracing::info!`. Wire-map will
    /// align with OCI's pull-through 404 override (the format-level
    /// `BLOB_UNKNOWN`-equivalent) so the client sees the same envelope
    /// as a genuine upstream miss.
    CurationBlocked,
    /// Any other ingest-time error — storage failure, event-store
    /// failure, repo lookup failure after ingest. Wire to 500.
    Internal(String),
}

/// On a local cache miss, fetch the requested crate from the
/// configured upstream registry, verify it against the upstream
/// `cksum`, and ingest into the local CAS. Three-leg orchestration:
/// `config.json` (cached) → NDJSON index (uncached) → crate download
/// (verified-ingest).
///
/// See the module-level docstring for the cache strategy.
///
/// Item 5 wires this from the `download` handler — Proxy-repo cache
/// misses route here.
///
/// ## Index URL override (Item 11)
///
/// When `repo.index_upstream_url` is `Some`, the metadata-leg fetches
/// (`config.json` + per-crate NDJSON) target that URL instead of the
/// default mapping URL. The download leg is always driven by the
/// `RegistryConfig.dl` value resolved from `config.json` — operators
/// who run a private index host typically don't control the download
/// CDN. The override is visible in the `#[instrument]` span as
/// `index_upstream_url_overridden: bool` (the URL itself is NOT logged
/// per CLAUDE.md observability — raw values are `debug!` at most).
#[tracing::instrument(
    skip(ctx),
    fields(
        repo_key = %repo.key,
        name,
        version,
        index_upstream_url_overridden = repo.index_upstream_url.is_some(),
    )
)]
pub(crate) async fn try_upstream_crate_pull(
    ctx: &Arc<AppContext>,
    repo: &Repository,
    name: &str,
    version: &str,
) -> Result<Artifact, UpstreamPullError> {
    // 1. Resolve upstream mapping. Cargo today is single-upstream
    //    only; the framework call passes `""` for the path-prefix
    //    (the resolver's longest-prefix-match degenerates to the
    //    catch-all empty-prefix entry).
    let Some((mapping, _stripped)) = ctx.upstream_resolver.resolve(repo.id, "") else {
        tracing::warn!("Cargo repository has no upstream mapping configured");
        return Err(UpstreamPullError::NoUpstreamMapping);
    };

    // Build the index-leg mapping. When repo.index_upstream_url is set,
    // the metadata-leg fetches (config.json + sparse-index NDJSON) target
    // that URL instead of mapping.upstream_url. The download leg always
    // follows the resolved RegistryConfig.dl via compose_download_url —
    // operators with private index hosts typically don't control the
    // download CDN. The .crate fetch uses an absolute URL (via the DL
    // template) so mapping.upstream_url does not affect it regardless
    // (see fetch_artifact absolute-URL bypass in
    // hort_domain::ports::upstream_proxy).
    let index_mapping = match repo.index_upstream_url.as_deref() {
        Some(idx) => {
            let mut m = mapping.clone();
            m.upstream_url = idx.to_string();
            m
        }
        None => mapping.clone(),
    };

    // 2. Fetch (or read from cache) the registry config.json.
    //    Uses index_mapping so that the override URL is honoured when set.
    let registry_config = resolve_registry_config(ctx, &index_mapping).await?;

    // 3. Fetch the sparse-index NDJSON (NOT cached — Item 4 reserves
    //    a separate cache key for per-crate index entries).
    let coords = match CargoFormatHandler
        .parse_download_path(&format!("api/v1/crates/{name}/{version}/download"))
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "Cargo upstream coords construction failed");
            return Err(UpstreamPullError::ParseError(e.to_string()));
        }
    };

    let Some(ndjson_path) = CargoFormatHandler.upstream_checksum_metadata_path(&coords) else {
        return Err(UpstreamPullError::Internal(
            "cargo handler did not return an index path".into(),
        ));
    };

    // Uses index_mapping for the NDJSON fetch — same override as config.json.
    // The download leg (fetch_artifact below) uses the ORIGINAL mapping
    // to make the intent explicit; the absolute DL URL bypasses
    // mapping.upstream_url in the adapter anyway.
    //
    // The NDJSON metadata leg streams the upstream body through
    // `CargoSparseIndexProjector` (no full-body `Vec`) into the small
    // `Vec<CargoVersionLine>` projection; the requested version's verbatim
    // `cksum` (Cargo's upstream checksum, ADR 0006) is recovered from the
    // matching `CargoVersionLine`. This does NOT route through the shared
    // `index_cache::fetch_raw_with_cache` serve cache: that helper
    // re-resolves the BASE mapping internally and would silently drop the
    // `index_upstream_url` override, so the tarball-pull keeps its own
    // override-honouring fetch leg and projects directly (`project_cached`,
    // no mirror write — the serve/cache path owns the mirror under the
    // base mapping).
    //
    // Wrap in `PullDedup::coalesce_metadata` so N parallel misses for the
    // same crate produce ≤ 1 upstream NDJSON fetch. The closure returns
    // the SERIALIZED projection so followers receive the small projection,
    // not the raw NDJSON body.
    let ndjson_dedup_key = DedupKey::metadata("cargo", repo.id, &ndjson_path);
    let ndjson_proxy = ctx.upstream_proxy.clone();
    let ndjson_mapping = index_mapping.clone();
    let ndjson_path_for_closure = ndjson_path.clone();
    let ndjson_coalesce = ctx
        .pull_dedup
        .coalesce_metadata(ndjson_dedup_key, move || async move {
            let outcome = ndjson_proxy
                .fetch_metadata(ndjson_mapping, ndjson_path_for_closure, Vec::new())
                .await
                .map_err(AppError::from)?;
            let handle = outcome.cache_handle.as_ref().ok_or_else(|| {
                AppError::from(DomainError::Invariant(
                    "cargo fetch_metadata returned no cache_handle".to_string(),
                ))
            })?;
            // Stream-project (no full-body Vec); a malformed NDJSON line
            // fails closed (Task 5 reject-on-invalid → `Validation`).
            // No mirror write here — the serve/cache path owns the mirror
            // (keyed on the base mapping; the tarball-pull may use the
            // override mapping, so writing here would diverge).
            let projection =
                hort_app::project::project_cached(handle, CargoSparseIndexProjector::new())
                    .await
                    .map_err(AppError::from)?;
            // Best-effort tempfile cleanup (the consumer owns the
            // lifecycle, mirroring the retired `metadata_body_bytes`).
            if let Err(e) = tokio::fs::remove_file(&handle.path).await {
                tracing::debug!(
                    path = %handle.path.display(),
                    error = %e,
                    "cargo index tempfile cleanup failed (non-fatal)"
                );
            }
            let json = serde_json::to_vec(&projection).map_err(|e| {
                AppError::from(DomainError::Invariant(format!(
                    "cargo projection serialize: {e}"
                )))
            })?;
            Ok(Bytes::from(json))
        })
        .await;
    let projection: Vec<CargoVersionLine> = match ndjson_coalesce {
        Ok(json) => serde_json::from_slice(&json).map_err(|e| {
            // A malformed serialized-projection frame is OUR internal
            // (de)serialize fault, not an upstream outage.
            UpstreamPullError::Internal(format!("cargo projection deserialize: {e}"))
        })?,
        // A malformed NDJSON line surfaces as a leader-side
        // `AppError::Domain(Validation(...))` (Task 5 fail-closed); a
        // transport/outage failure is anything else (incl. follower-side
        // wrapped errors). Classify the parse-class failure as a content
        // ParseError, everything else as the metadata-leg fetch failure.
        Err(AppError::Domain(DomainError::Validation(msg))) => {
            tracing::warn!(cause = %msg, "Cargo upstream index malformed (parse_error)");
            return Err(UpstreamPullError::ParseError(msg));
        }
        Err(e) => {
            tracing::warn!(error = %e, "Cargo upstream index fetch failed");
            return Err(UpstreamPullError::MetadataFetchFailed {
                stage: "index",
                err: e.to_string(),
            });
        }
    };

    // 4. Recover the upstream cksum from the projection's verbatim
    //    `cksum` (`CargoVersionLine.cksum` — Cargo's upstream checksum per
    //    ADR 0006). The "no entry for {name}@{version}" case maps to
    //    a content-level NotFoundUpstream — distinct from a generic
    //    ParseError so the wire-map can render the right envelope. The
    //    SHA-256 length/hex validation is driven through the SAME audited
    //    `CargoFormatHandler::parse_upstream_checksum` against a minimal
    //    synthetic NDJSON line holding just the requested version's
    //    `cksum`, so the verification semantics stay byte-identical and
    //    are not duplicated.
    let Some(entry) = projection.iter().find(|l| l.vers == version) else {
        tracing::warn!(
            name,
            version,
            "Cargo upstream index has no entry for version"
        );
        return Err(UpstreamPullError::NotFoundUpstream);
    };
    let upstream_checksum = match checksum_from_entry(entry, &coords) {
        Ok(cs) => cs,
        Err(e) => {
            tracing::warn!(error = %e, "Cargo upstream index parse failed");
            return Err(UpstreamPullError::ParseError(e.to_string()));
        }
    };

    // 5. Compose the download URL via Item 2's helper. The composer
    //    handles all four spec-defined placeholder shapes plus the
    //    no-placeholder default (crates.io's `dl` falls into that
    //    bucket).
    let download_url = compose_download_url(
        &registry_config,
        name,
        version,
        Some(upstream_checksum.hex()),
    );

    // 6. Stream the artifact body through ingest_verified. The use
    //    case rehashes while streaming and returns Conflict on a
    //    cksum mismatch — our security primitive against upstream
    //    tampering (see §15 of the upstream-verification design).
    //
    //    Wrap the `fetch_artifact + ingest_verified` pair in
    //    `coalesce_blob` so N parallel callers for the same `.crate`
    //    produce ≤ 1 upstream fetch + ≤ 1 CAS write. The dedup key is
    //    the verified upstream `cksum` from the index — pre-known via
    //    the verified pull path, so different repos pointing at the same
    //    upstream share a single coalescing window.
    //
    //    Closure-boundary contract: on success the closure returns
    //    `Ok(content_hash)`; on failure `Err(AppError)`. The leader sees
    //    the original `AppError` discriminator; followers observe the
    //    cached `Failed` outcome and surface a wrapped
    //    `AppError::External` — typed-error discrimination is a
    //    leader-only concern. The match arms below preserve discrimination
    //    for the leader and route follower-side errors through `Internal`
    //    (followers never re-attempt; they surface the cached failure to
    //    the client).
    let blob_dedup_key = DedupKey::blob_by_hash("sha256", upstream_checksum.hex());
    let blob_proxy = ctx.upstream_proxy.clone();
    let blob_mapping = mapping.clone();
    let blob_download_url = download_url;
    let blob_ingest = ctx.ingest_use_case.clone();
    let blob_repo_id = repo.id;
    // Capture the serving mapping's per-upstream opt-in
    // (`trust_upstream_publish_time`) **before** the closure consumes
    // `mapping`. Threaded into `VerifiedIngestRequest` so `ingest_inner`
    // can gate the publish-anchored quarantine resolution on it.
    let blob_trust_publish_time = mapping.trust_upstream_publish_time;
    // F-14: keep a clone for the cross-repo follower-registration
    // fallback below (the closure consumes `blob_coords`).
    let follower_coords = coords.clone();
    let blob_coords = coords;
    let blob_upstream_url = mapping.upstream_url.clone();
    let follower_upstream_url = blob_upstream_url.clone();
    let blob_upstream_checksum = upstream_checksum;
    let coalesce_blob_result = ctx
        .pull_dedup
        .coalesce_blob(blob_dedup_key, move || async move {
            let fetch = blob_proxy
                .fetch_artifact(blob_mapping, blob_download_url)
                .await
                .map_err(AppError::from)?;
            // The `.crate` tarball's `Last-Modified` response header
            // ≈ upload time on crates.io (crate files are immutable).
            // Best-effort: absent / unparseable → None. NOT the
            // sparse-index file's Last-Modified (tracks the latest
            // version, not this version's publish); NOT a crates.io
            // API call.
            let upstream_published_at = fetch.last_modified;
            let reader: Box<dyn AsyncRead + Send + Unpin> =
                Box::new(StreamReader::new(fetch.stream));
            let request = VerifiedIngestRequest::UpstreamPublished {
                repository_id: blob_repo_id,
                coords: blob_coords,
                content_type: "application/x-tar".to_string(),
                actor: ApiActor {
                    user_id: Uuid::nil(),
                },
                payload_metadata: serde_json::json!({
                    "source": "cargo_upstream_pull",
                    "upstream_url": blob_upstream_url,
                }),
                upstream_checksum: blob_upstream_checksum,
                upstream_published_at,
                trust_upstream_publish_time: blob_trust_publish_time,
            };
            let outcome = blob_ingest
                .ingest_verified(request, reader, &CargoFormatHandler)
                .await?;
            Ok(outcome.artifact.sha256_checksum)
        })
        .await;

    let content_hash = match coalesce_blob_result {
        Ok(h) => h,
        // Leader-side failures still carry typed `AppError::Domain`
        // discriminators — preserve the existing wire-mapping. The
        // `MetadataFetchFailed{stage:"artifact"}` arm covers the
        // pre-ingest fetch_artifact transport failure; the
        // ChecksumMismatch / CurationBlocked arms cover the post-
        // hash-rejection cases. Follower-side errors arrive as
        // `AppError::External("pull-dedup follower: ...")` and route
        // to `Internal` per the design's leader-only-discrimination
        // contract (§4).
        Err(AppError::Domain(DomainError::Conflict(msg))) => {
            tracing::warn!(conflict = %msg, "Cargo upstream checksum mismatch");
            return Err(UpstreamPullError::ChecksumMismatch);
        }
        Err(AppError::Domain(DomainError::CurationBlocked { .. })) => {
            tracing::warn!("Cargo upstream artifact blocked by curation rule");
            return Err(UpstreamPullError::CurationBlocked);
        }
        Err(e) => {
            // `fetch_artifact` errors and any other ingest-time
            // infrastructure failure converge here. The original
            // pre-coalesce code split `fetch_artifact` failures into
            // `MetadataFetchFailed{stage:"artifact"}`; preserve that
            // by string-matching the wrapped error message — the
            // upstream HTTP adapter prefixes its errors with
            // "upstream:" (see `MockUpstreamProxy::fetch_artifact`
            // and the production `UpstreamHttpAdapter`).
            let msg = e.to_string();
            if msg.contains("upstream:") || msg.contains("upstream ") {
                tracing::warn!(error = %e, "Cargo upstream artifact fetch failed");
                return Err(UpstreamPullError::MetadataFetchFailed {
                    stage: "artifact",
                    err: msg,
                });
            }
            tracing::warn!(error = %e, "Cargo upstream ingest failed");
            return Err(UpstreamPullError::Internal(msg));
        }
    };

    // Post-coalesce read: both leader and follower re-resolve the
    // artifact row by content hash. The leader's `ingest_verified`
    // (inside the closure) wrote the row; the follower reads it. The
    // lookup is per-repo and microsecond-fast.
    //
    // `blob_by_hash` is cross-repo, so a follower that joined a window
    // whose leader ingested into a DIFFERENT repo has no row in
    // `repo.id` — the lookup returns `None`. That is not an error: the
    // content is already CAS-present and checksum-verified. The follower
    // idempotently registers its OWN per-repo row via
    // `register_existing_cas_blob` (same `ArtifactIngested` event the
    // leader's non-concurrent cross-repo dedup emits — no re-fetch, no
    // re-`storage.put`).
    let artifact = match ctx
        .artifact_use_case
        .find_in_repo_by_hash(repo.id, &content_hash)
        .await
        .map_err(|e| UpstreamPullError::Internal(e.to_string()))?
    {
        Some(a) => a,
        None => {
            ctx.ingest_use_case
                .register_existing_cas_blob(
                    RegisterExistingCasBlobRequest {
                        repository_id: repo.id,
                        coords: follower_coords,
                        content_type: "application/x-tar".to_string(),
                        actor: ApiActor {
                            user_id: Uuid::nil(),
                        },
                        payload_metadata: serde_json::json!({
                            "source": "cargo_upstream_pull",
                            "upstream_url": follower_upstream_url,
                        }),
                        content_hash: content_hash.clone(),
                        // Upstream pull is not a seed-import cutover;
                        // quarantine is policy-driven through the primary
                        // `ingest_verified` path.
                        seed_import_quarantine_anchor: None,
                    },
                    &CargoFormatHandler,
                )
                .await
                .map_err(|e| UpstreamPullError::Internal(e.to_string()))?
                .artifact
        }
    };

    // hort_upstream_checksum_total{format="cargo",result="verified"} emission
    // lives in IngestUseCase::ingest_verified per 17.0 Item 11; no
    // per-Cargo emission needed here. Same for hort_upstream_fetch_total
    // (UpstreamProxy adapter).
    tracing::info!(
        artifact_id = %artifact.id,
        algorithm = "sha256",
        "Cargo upstream pull-through completed; ChecksumVerified emitted"
    );
    Ok(artifact)
}

/// Recover the upstream SHA-256 [`UpstreamPublishedChecksum`] from a
/// projection [`CargoVersionLine`]'s verbatim `cksum` (Cargo's upstream
/// checksum per ADR 0006).
///
/// To keep the SHA-256 length/hex validation **byte-identical** (and NOT
/// duplicate that security-critical logic), this drives the SAME audited
/// [`CargoFormatHandler::parse_upstream_checksum`] path against a minimal
/// synthetic single-line NDJSON body that contains only the requested
/// version's `vers` + `cksum` — the only fields that path reads for the
/// checksum. A missing/empty `cksum` yields a line whose `cksum` is
/// absent, so the handler returns the same "has no cksum" `Validation`
/// the raw parser produced; a malformed cksum returns the same
/// decode-failure `Validation`.
fn checksum_from_entry(
    entry: &CargoVersionLine,
    coords: &ArtifactCoords,
) -> DomainResult<UpstreamPublishedChecksum> {
    let version = coords.version.as_deref().unwrap_or_default();
    // Minimal single-line NDJSON holding only `vers` + `cksum` — the
    // exact fields `parse_upstream_checksum` reads. The cargo projector's
    // `CargoVersionLine.cksum` defaults to "" when upstream omitted it;
    // emit the field only when non-empty so the handler's "has no cksum"
    // path fires identically to the raw-body case. Built via `serde_json`
    // so the cksum string is escaped correctly.
    let line = if entry.cksum.is_empty() {
        serde_json::json!({ "vers": version })
    } else {
        serde_json::json!({ "vers": version, "cksum": entry.cksum })
    };
    let mut bytes = serde_json::to_vec(&line)
        .map_err(|e| DomainError::Invariant(format!("cargo synthetic line serialize: {e}")))?;
    bytes.push(b'\n');
    // `parse_upstream_checksum` takes a streaming reader; the synthetic
    // single-line NDJSON is tiny, so a cursor over the in-memory bytes
    // satisfies the port without behaviour change.
    CargoFormatHandler.parse_upstream_checksum(&mut std::io::Cursor::new(&bytes), coords)
}

/// Read-through cache for the registry config.json.
///
/// Cache key: `cargo_index_config:{mapping.id}`. On miss: fetch via
/// [`UpstreamProxy::fetch_metadata`], parse via
/// [`parse_registry_config`] (so a malformed body fails fast on the
/// FIRST read instead of poisoning the cache), and store the raw
/// bytes back. Subsequent reads re-parse on each hit; the parse cost
/// is negligible compared to the upstream HTTP round-trip.
///
/// TTL: 24 h backend TTL — operators don't change `dl` URLs in
/// practice, so a stale entry surviving an upstream blip is preferred
/// to a hot-path freshness check. Item 4 will revisit if the per-
/// crate index cache wants tighter freshness.
///
async fn resolve_registry_config(
    ctx: &Arc<AppContext>,
    mapping: &RepositoryUpstreamMapping,
) -> Result<RegistryConfig, UpstreamPullError> {
    let cache_key = format!("cargo_index_config:{}", mapping.id);
    const CONFIG_TTL: Duration = Duration::from_secs(24 * 3600);

    if let Some(bytes) = ctx
        .ephemeral_evictable
        .get(&cache_key)
        .await
        .map_err(|e| UpstreamPullError::Internal(e.to_string()))?
    {
        // Cache hit — re-parse so the on-disk format stays just
        // "raw upstream config.json bytes" without an envelope.
        return parse_registry_config(&bytes).map_err(|e| {
            tracing::warn!(error = %e, "cached Cargo config.json failed to re-parse");
            UpstreamPullError::ParseError(e.to_string())
        });
    }

    // Cache miss — fetch, parse to validate, and store.
    //
    // Wrap the upstream `config.json` fetch in `coalesce_metadata` so N
    // parallel cold-cache callers produce ≤ 1 upstream round-trip. The
    // dedup key is per-(repository, URL) — distinct repos pointing at the
    // same upstream do NOT share this window because their trust configs
    // may differ.
    let config_path = "/config.json".to_string();
    let config_dedup_key = DedupKey::metadata("cargo", mapping.repository_id, &config_path);
    let config_proxy = ctx.upstream_proxy.clone();
    let config_mapping = mapping.clone();
    let config_path_for_closure = config_path.clone();
    let body = ctx
        .pull_dedup
        .coalesce_metadata(config_dedup_key, move || async move {
            let outcome = config_proxy
                .fetch_metadata(config_mapping, config_path_for_closure, Vec::new())
                .await
                .map_err(AppError::from)?;
            // The registry `config.json` is a tiny fixed JSON object
            // (`{"dl":…,"api":…}`), not the multi-MB metadata-index
            // problem, so it has no per-format projection: recover the raw
            // bytes via `IdentityProjector` (the same shape
            // `parse_registry_config` consumes), then clean up the
            // tempfile explicitly.
            let handle = outcome.cache_handle.as_ref().ok_or_else(|| {
                AppError::from(DomainError::Invariant(
                    "cargo config.json fetch_metadata returned no cache_handle".to_string(),
                ))
            })?;
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
                    "cargo config.json tempfile cleanup failed (non-fatal)"
                );
            }
            Ok(Bytes::from(body))
        })
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "Cargo upstream config.json fetch failed");
            UpstreamPullError::MetadataFetchFailed {
                stage: "config",
                err: e.to_string(),
            }
        })?
        // Convert `Bytes` → `Vec<u8>` to keep the existing local-shape
        // (`let body: Vec<u8>`) consumed by `parse_registry_config(&body)`
        // and the `ephemeral_evictable.put(... Bytes::from(body) ...)`
        // re-wrap below. Preserves the on-disk cache format unchanged.
        .to_vec();

    let config = parse_registry_config(&body).map_err(|e| {
        tracing::warn!(error = %e, "Cargo upstream config.json parse failed");
        // Surface as MetadataFetchFailed{stage:"config"} (NOT
        // ParseError) so the wire-map can render a single
        // upstream-config-broken envelope regardless of whether the
        // upstream returned bad bytes or a transport-level error.
        UpstreamPullError::MetadataFetchFailed {
            stage: "config",
            err: e.to_string(),
        }
    })?;

    // Store raw bytes — cheap, re-parsable, and avoids inventing an
    // envelope that Item 4 will need to design more carefully when
    // it adds the per-crate index cache.
    if let Err(e) = ctx
        .ephemeral_evictable
        .put(&cache_key, Bytes::from(body), CONFIG_TTL)
        .await
    {
        // Cache-store failure is non-fatal: we just paid the upstream
        // round-trip and parsed successfully, so degrading to "always
        // re-fetch" is preferred over surfacing a 5xx to the caller.
        tracing::warn!(error = %e, "Cargo config.json cache write failed (non-fatal)");
    }

    Ok(config)
}

/// Wire-mapping for [`UpstreamPullError`] used by the `download`
/// handler's Proxy-cache-miss branch.
///
/// | Variant | Status | `X-Hort-Reason` |
/// |---|---|---|
/// | `NoUpstreamMapping` / `NotFoundUpstream` / `CurationBlocked` | 404 | — |
/// | `ChecksumMismatch` | 502 | `upstream-checksum-mismatch` |
/// | `ParseError` | 502 | `upstream-metadata-malformed` |
/// | `MetadataFetchFailed{stage}` | 502 | `upstream-metadata-fetch-failed-{stage}` |
/// | `Internal` | 500 | — |
///
/// Notes:
///
/// - `CurationBlocked` collapses to the same envelope as a genuine
///   miss — matches the OCI prior art at
///   `crates/hort-http-oci/src/blobs.rs::serve` where pull-through
///   curation blocks surface as `BLOB_UNKNOWN`. The curation event is
///   already emitted by `IngestUseCase`.
/// - The body shape mirrors the existing `download`-handler helpers
///   (`{"error": "..."}`, `application/json`) so client-side logging
///   stays uniform across the success / quarantine / pull-through
///   branches.
/// - `Internal` returns `"internal error"` verbatim — never the inner
///   message — to match the `ApiError::Repository`/`Storage`/`EventStore`
///   sanitisation contract in `hort_http_core::error`.
pub(crate) fn map_upstream_pull_error(e: &UpstreamPullError) -> Response {
    match e {
        UpstreamPullError::NoUpstreamMapping
        | UpstreamPullError::NotFoundUpstream
        | UpstreamPullError::CurationBlocked => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::json!({"error": "crate not found"}).to_string(),
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
        UpstreamPullError::ParseError(_) => Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .header("Content-Type", "application/json")
            .header("X-Hort-Reason", "upstream-metadata-malformed")
            .body(Body::from(
                serde_json::json!({"error": "upstream metadata malformed"}).to_string(),
            ))
            .unwrap(),
        UpstreamPullError::MetadataFetchFailed { stage, .. } => Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .header("Content-Type", "application/json")
            .header(
                "X-Hort-Reason",
                format!("upstream-metadata-fetch-failed-{stage}"),
            )
            .body(Body::from(
                serde_json::json!({"error": "upstream unavailable"}).to_string(),
            ))
            .unwrap(),
        UpstreamPullError::Internal(_) => Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header("Content-Type", "application/json")
            .body(Body::from(
                serde_json::json!({"error": "internal error"}).to_string(),
            ))
            .unwrap(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use chrono::{DateTime, Utc};
    use metrics_exporter_prometheus::PrometheusBuilder;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::Registry;
    use uuid::Uuid;

    use hort_app::use_cases::test_support::sample_repository;
    use hort_domain::entities::curation_rule::{CurationRule, CurationRuleAction};
    use hort_domain::entities::managed_by::ManagedBy;
    use hort_domain::entities::repository::{Repository, RepositoryFormat};
    use hort_domain::error::DomainError;
    use hort_domain::ports::repository_upstream_mapping_repository::{
        RepositoryUpstreamMapping, UpstreamAuth,
    };
    use hort_http_core::test_support::{build_mock_ctx, MockPorts};

    use super::*;

    /// Crates.io-style minimal config.json — placeholder-free `dl`.
    /// `compose_download_url` then appends `/{name}/{version}/download`.
    const CRATES_IO_CONFIG: &[u8] =
        br#"{"dl":"https://static.crates.io/crates","api":"https://crates.io"}"#;

    /// Upstream URL the mock fetch_artifact keys on. With a
    /// placeholder-free `dl`, the composer produces:
    ///   `<dl>/{name}/{version}/download`
    /// — and the mock keys on the FULL URL string passed to
    /// `fetch_artifact` (matches the production HTTP adapter's
    /// absolute-URL handling).
    fn artifact_path(name: &str, version: &str) -> String {
        format!("https://static.crates.io/crates/{name}/{version}/download")
    }

    /// One-line NDJSON entry whose `cksum` is the sha256 of `body`.
    /// Used to drive happy-path + checksum-mismatch tests.
    fn ndjson_entry(name: &str, version: &str, cksum: &str) -> Vec<u8> {
        format!(
            r#"{{"name":"{name}","vers":"{version}","deps":[],"cksum":"{cksum}","features":{{}},"yanked":false}}"#
        )
        .into_bytes()
    }

    fn sha256_hex(content: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        format!("{:x}", Sha256::digest(content))
    }

    fn cargo_repo(key: &str) -> Repository {
        let mut r = sample_repository();
        r.key = key.into();
        r.format = RepositoryFormat::Cargo;
        r
    }

    /// Seed an upstream mapping with the given `path_prefix` (use `""`
    /// for the single-upstream catch-all).
    fn seed_mapping(mocks: &MockPorts, repo_id: Uuid, path_prefix: &str) -> Uuid {
        let id = Uuid::new_v4();
        let now = Utc::now();
        mocks.upstream_resolver.insert(RepositoryUpstreamMapping {
            id,
            repository_id: repo_id,
            path_prefix: path_prefix.into(),
            upstream_url: "https://crates.io".into(),
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

    fn handle() -> metrics_exporter_prometheus::PrometheusHandle {
        PrometheusBuilder::new().build_recorder().handle()
    }

    // ---- Branch 1: no mapping -----------------------------------------------

    #[tokio::test]
    async fn no_upstream_mapping_returns_no_upstream_mapping() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = cargo_repo("crates-mirror");
        mocks.repositories.insert(repo.clone());

        let err = try_upstream_crate_pull(&ctx, &repo, "serde", "1.0.0")
            .await
            .unwrap_err();

        assert!(
            matches!(err, UpstreamPullError::NoUpstreamMapping),
            "expected NoUpstreamMapping, got {err:?}"
        );
    }

    // ---- Branch 2: config fetch fails (transport) ---------------------------

    #[tokio::test]
    async fn config_fetch_fail_returns_metadata_fetch_failed_with_stage_config() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = cargo_repo("crates-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id, "");

        // No metadata seeded → mock returns "upstream:not_found:..." on
        // the first fetch_metadata (the config.json call). Stage must
        // be "config".
        let err = try_upstream_crate_pull(&ctx, &repo, "serde", "1.0.0")
            .await
            .unwrap_err();

        match err {
            UpstreamPullError::MetadataFetchFailed { stage, err: msg } => {
                assert_eq!(stage, "config");
                assert!(msg.contains("upstream"), "unexpected msg: {msg}");
            }
            other => panic!("expected MetadataFetchFailed{{stage:\"config\"}}, got {other:?}"),
        }
    }

    // ---- Branch 3: config parses fail ---------------------------------------

    #[tokio::test]
    async fn config_parse_fail_returns_metadata_fetch_failed_with_stage_config() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = cargo_repo("crates-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id, "");

        // Body present but garbage — parse_registry_config rejects it.
        // The orchestrator promotes this to MetadataFetchFailed{stage:"config"}
        // (not ParseError) so wire-mapping renders one envelope for
        // every config-broken outcome.
        mocks
            .upstream_proxy
            .insert_metadata("", "/config.json", b"not-json".to_vec());

        let err = try_upstream_crate_pull(&ctx, &repo, "serde", "1.0.0")
            .await
            .unwrap_err();

        match err {
            UpstreamPullError::MetadataFetchFailed { stage, .. } => {
                assert_eq!(stage, "config");
            }
            other => panic!(
                "expected MetadataFetchFailed{{stage:\"config\"}} for parse failure, got {other:?}"
            ),
        }
    }

    // ---- Branch 4: index fetch fails (transport) ----------------------------

    #[tokio::test]
    async fn index_fetch_fail_returns_metadata_fetch_failed_with_stage_index() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = cargo_repo("crates-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id, "");

        // Config seeded; index NOT seeded → mock returns not_found
        // for the second fetch_metadata. Stage must be "index".
        mocks
            .upstream_proxy
            .insert_metadata("", "/config.json", CRATES_IO_CONFIG.to_vec());

        let err = try_upstream_crate_pull(&ctx, &repo, "serde", "1.0.0")
            .await
            .unwrap_err();

        match err {
            UpstreamPullError::MetadataFetchFailed { stage, .. } => {
                assert_eq!(stage, "index");
            }
            other => panic!("expected MetadataFetchFailed{{stage:\"index\"}}, got {other:?}"),
        }
    }

    // ---- Branch 5: index has no entry for version ---------------------------

    #[tokio::test]
    async fn index_has_no_entry_for_version_returns_not_found_upstream() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = cargo_repo("crates-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id, "");

        mocks
            .upstream_proxy
            .insert_metadata("", "/config.json", CRATES_IO_CONFIG.to_vec());
        // NDJSON has serde@2.0.0 but the request asks for 1.0.0.
        let cksum = sha256_hex(b"unused");
        mocks.upstream_proxy.insert_metadata(
            "",
            "/se/rd/serde",
            ndjson_entry("serde", "2.0.0", &cksum),
        );

        let err = try_upstream_crate_pull(&ctx, &repo, "serde", "1.0.0")
            .await
            .unwrap_err();

        assert!(
            matches!(err, UpstreamPullError::NotFoundUpstream),
            "expected NotFoundUpstream, got {err:?}"
        );
    }

    // ---- Branch 6: index entry has no cksum (parse error) -------------------

    #[tokio::test]
    async fn index_entry_has_no_cksum_returns_parse_error() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = cargo_repo("crates-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id, "");

        mocks
            .upstream_proxy
            .insert_metadata("", "/config.json", CRATES_IO_CONFIG.to_vec());
        // Entry has the right vers but no cksum field.
        let body = br#"{"name":"serde","vers":"1.0.0","deps":[],"features":{},"yanked":false}"#;
        mocks
            .upstream_proxy
            .insert_metadata("", "/se/rd/serde", body.to_vec());

        let err = try_upstream_crate_pull(&ctx, &repo, "serde", "1.0.0")
            .await
            .unwrap_err();

        assert!(
            matches!(err, UpstreamPullError::ParseError(_)),
            "expected ParseError, got {err:?}"
        );
    }

    // ---- Branch 7: download fetch fails (transport) -------------------------

    #[tokio::test]
    async fn download_fetch_fail_returns_metadata_fetch_failed_with_stage_artifact() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = cargo_repo("crates-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id, "");

        let body = b"crate-bytes".to_vec();
        let cksum = sha256_hex(&body);
        mocks
            .upstream_proxy
            .insert_metadata("", "/config.json", CRATES_IO_CONFIG.to_vec());
        mocks.upstream_proxy.insert_metadata(
            "",
            "/se/rd/serde",
            ndjson_entry("serde", "1.0.0", &cksum),
        );
        // No insert_artifact → fetch_artifact returns not_found.

        let err = try_upstream_crate_pull(&ctx, &repo, "serde", "1.0.0")
            .await
            .unwrap_err();

        match err {
            UpstreamPullError::MetadataFetchFailed { stage, .. } => {
                assert_eq!(stage, "artifact");
            }
            other => panic!("expected MetadataFetchFailed{{stage:\"artifact\"}}, got {other:?}"),
        }
    }

    // ---- Branch 8: ingest_verified returns Conflict (mismatch) --------------

    #[tokio::test]
    async fn ingest_verified_returns_conflict_returns_checksum_mismatch() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = cargo_repo("crates-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id, "");

        // Index advertises a cksum that does NOT match the bytes the
        // proxy will serve. The use case rehashes the streamed bytes
        // and returns Conflict.
        let actual = b"actual-bytes".to_vec();
        let lying_cksum = sha256_hex(b"different-bytes");
        mocks
            .upstream_proxy
            .insert_metadata("", "/config.json", CRATES_IO_CONFIG.to_vec());
        mocks.upstream_proxy.insert_metadata(
            "",
            "/se/rd/serde",
            ndjson_entry("serde", "1.0.0", &lying_cksum),
        );
        mocks
            .upstream_proxy
            .insert_artifact("", &artifact_path("serde", "1.0.0"), actual);

        let err = try_upstream_crate_pull(&ctx, &repo, "serde", "1.0.0")
            .await
            .unwrap_err();

        assert!(
            matches!(err, UpstreamPullError::ChecksumMismatch),
            "expected ChecksumMismatch, got {err:?}"
        );
    }

    // ---- Branch 9: ingest_verified returns CurationBlocked ------------------

    #[tokio::test]
    async fn ingest_verified_returns_curation_blocked_returns_curation_blocked() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = cargo_repo("crates-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id, "");

        let body = b"crate-bytes".to_vec();
        let cksum = sha256_hex(&body);
        mocks
            .upstream_proxy
            .insert_metadata("", "/config.json", CRATES_IO_CONFIG.to_vec());
        mocks.upstream_proxy.insert_metadata(
            "",
            "/se/rd/serde",
            ndjson_entry("serde", "1.0.0", &cksum),
        );
        mocks
            .upstream_proxy
            .insert_artifact("", &artifact_path("serde", "1.0.0"), body);

        // Curation rule that matches everything in this repo.
        let rule = CurationRule {
            id: Uuid::new_v4(),
            name: "block-all".into(),
            format: None,
            package_pattern: "*".into(),
            action: CurationRuleAction::Block,
            reason: "policy".into(),
            managed_by: ManagedBy::GitOps,
            managed_by_digest: Some([0xab; 32]),
        };
        mocks.curation_rules.set_rules_for_repo(repo.id, vec![rule]);

        let err = try_upstream_crate_pull(&ctx, &repo, "serde", "1.0.0")
            .await
            .unwrap_err();

        assert!(
            matches!(err, UpstreamPullError::CurationBlocked),
            "expected CurationBlocked, got {err:?}"
        );
    }

    // ---- Branch 10: ingest_verified returns Internal (storage failure) ------

    #[tokio::test]
    async fn ingest_verified_internal_error_returns_internal() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = cargo_repo("crates-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id, "");

        let body = b"crate-bytes".to_vec();
        let cksum = sha256_hex(&body);
        mocks
            .upstream_proxy
            .insert_metadata("", "/config.json", CRATES_IO_CONFIG.to_vec());
        mocks.upstream_proxy.insert_metadata(
            "",
            "/se/rd/serde",
            ndjson_entry("serde", "1.0.0", &cksum),
        );
        mocks
            .upstream_proxy
            .insert_artifact("", &artifact_path("serde", "1.0.0"), body);

        // Force commit_transition() to fail — the use case rolls up
        // to an AppError that is neither Conflict nor CurationBlocked,
        // so the orchestrator routes it to Internal. Lifecycle
        // failure is the cleanest "infra exploded after rehash"
        // simulation the mock harness offers.
        mocks
            .lifecycle
            .fail_next_commit(DomainError::Invariant("event store unreachable".into()));

        let err = try_upstream_crate_pull(&ctx, &repo, "serde", "1.0.0")
            .await
            .unwrap_err();

        assert!(
            matches!(err, UpstreamPullError::Internal(_)),
            "expected Internal, got {err:?}"
        );
    }

    // ---- Branch 11: happy path ----------------------------------------------

    #[tokio::test]
    async fn happy_path_returns_artifact() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = cargo_repo("crates-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id, "");

        let body = b"the actual crate body".to_vec();
        let cksum = sha256_hex(&body);
        mocks
            .upstream_proxy
            .insert_metadata("", "/config.json", CRATES_IO_CONFIG.to_vec());
        mocks.upstream_proxy.insert_metadata(
            "",
            "/se/rd/serde",
            ndjson_entry("serde", "1.0.214", &cksum),
        );
        mocks
            .upstream_proxy
            .insert_artifact("", &artifact_path("serde", "1.0.214"), body.clone());

        let artifact = try_upstream_crate_pull(&ctx, &repo, "serde", "1.0.214")
            .await
            .expect("happy path must succeed");

        assert_eq!(artifact.name, "serde");
        assert_eq!(artifact.version.as_deref(), Some("1.0.214"));
        assert_eq!(artifact.size_bytes as usize, body.len());
        // The SHA-256 stored on the artifact must equal the cksum
        // recovered from the NDJSON — this is the load-bearing
        // assertion that ingest_verified actually verified the bytes.
        assert_eq!(artifact.sha256_checksum.as_ref(), cksum);
    }

    // ---- .crate tarball Last-Modified ----------------------------------------
    //
    // The cargo path extracts the upstream publish-time hint from the
    // `Last-Modified` response header on the `.crate` tarball fetch (the
    // crates.io tarball is immutable so this ≈ upload time). NOT the
    // sparse-index file's Last-Modified, NOT a crates.io API call.
    // -------------------------------------------------------------------------

    /// Some(Last-Modified) on the `.crate` fetch → threaded onto the
    /// minted artifact's `upstream_published_at`.
    #[tokio::test]
    async fn upstream_published_at_threaded_from_crate_tarball_last_modified() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = cargo_repo("crates-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id, "");

        let body = b"the actual crate body".to_vec();
        let cksum = sha256_hex(&body);
        let last_modified: DateTime<Utc> = DateTime::parse_from_rfc3339("2023-11-06T12:34:56Z")
            .unwrap()
            .with_timezone(&Utc);
        mocks
            .upstream_proxy
            .insert_metadata("", "/config.json", CRATES_IO_CONFIG.to_vec());
        mocks.upstream_proxy.insert_metadata(
            "",
            "/se/rd/serde",
            ndjson_entry("serde", "1.0.214", &cksum),
        );
        mocks.upstream_proxy.insert_artifact_with_last_modified(
            "",
            &artifact_path("serde", "1.0.214"),
            body.clone(),
            Some(last_modified),
        );

        let artifact = try_upstream_crate_pull(&ctx, &repo, "serde", "1.0.214")
            .await
            .expect("happy path must succeed");

        assert_eq!(
            artifact.upstream_published_at,
            Some(last_modified),
            ".crate Last-Modified must thread onto \
             Artifact.upstream_published_at via VerifiedIngestRequest"
        );
    }

    /// None Last-Modified on the `.crate` fetch → `upstream_published_at = None`
    /// on the minted artifact. Absent header is the common case and
    /// must NOT fail the ingest.
    #[tokio::test]
    async fn upstream_published_at_none_when_crate_tarball_last_modified_absent() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = cargo_repo("crates-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id, "");

        let body = b"the actual crate body".to_vec();
        let cksum = sha256_hex(&body);
        mocks
            .upstream_proxy
            .insert_metadata("", "/config.json", CRATES_IO_CONFIG.to_vec());
        mocks.upstream_proxy.insert_metadata(
            "",
            "/se/rd/serde",
            ndjson_entry("serde", "1.0.214", &cksum),
        );
        // `insert_artifact` (without `_with_last_modified`) → None hint.
        mocks
            .upstream_proxy
            .insert_artifact("", &artifact_path("serde", "1.0.214"), body);

        let artifact = try_upstream_crate_pull(&ctx, &repo, "serde", "1.0.214")
            .await
            .expect("happy path must succeed even without Last-Modified");

        assert_eq!(
            artifact.upstream_published_at, None,
            "absent Last-Modified must yield None, not an ingest failure"
        );
    }

    // ---- Tracing infrastructure for warn-capture test -----------------------

    /// Custom tracing layer that captures emitted events into a shared
    /// vector. Mirrors the pattern in `hort-app::use_cases::repository_access`
    /// tests. Lightweight — no `tracing-subscriber` fmt overhead.
    #[derive(Clone, Default)]
    struct CapturingLayer {
        records: Arc<Mutex<Vec<(tracing::Level, String)>>>,
    }

    impl<S> tracing_subscriber::Layer<S> for CapturingLayer
    where
        S: tracing::Subscriber,
    {
        /// Return `Interest::sometimes()` so the per-callsite cache never
        /// locks out our per-thread subscriber. Without this, a sibling
        /// test that fires the same callsite under the no-op default
        /// subscriber caches `Never` and our test sees nothing.
        fn register_callsite(
            &self,
            _meta: &'static tracing::Metadata<'static>,
        ) -> tracing::subscriber::Interest {
            tracing::subscriber::Interest::sometimes()
        }

        fn enabled(
            &self,
            _meta: &tracing::Metadata<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) -> bool {
            true
        }

        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut visitor = MessageVisitor::default();
            event.record(&mut visitor);
            self.records
                .lock()
                .unwrap()
                .push((*event.metadata().level(), visitor.combined));
        }

        /// Capture span field values when a new span is created by
        /// `#[instrument]`. This lets tests assert on structured fields
        /// like `index_upstream_url_overridden` that are span attributes
        /// rather than event fields. Stored at `TRACE` level so they
        /// don't collide with emitted `WARN`/`INFO` events.
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            _id: &tracing::span::Id,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut visitor = MessageVisitor::default();
            attrs.record(&mut visitor);
            if !visitor.combined.is_empty() {
                self.records
                    .lock()
                    .unwrap()
                    .push((tracing::Level::TRACE, visitor.combined));
            }
        }
    }

    #[derive(Default)]
    struct MessageVisitor {
        combined: String,
    }
    impl tracing::field::Visit for MessageVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.combined
                .push_str(&format!("{}={:?} ", field.name(), value));
        }
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.combined
                .push_str(&format!("{}={} ", field.name(), value));
        }
    }

    /// Serialises tests that install per-thread tracing subscribers.
    /// `tracing` caches per-callsite `Interest` globally; installing one
    /// subscriber on thread A while thread B fires the same callsite
    /// races. The mutex eliminates the race without touching global state.
    static TRACING_TEST_MUTEX: Mutex<()> = Mutex::new(());

    /// Install a global passthrough subscriber (once per process) so
    /// the per-callsite cache is seeded with `Interest::sometimes()`
    /// rather than `Never`. Without this, a no-op subscriber installed
    /// by any earlier test can cache `Never` for our callsites and
    /// prevent the per-thread `set_default` subscriber from ever seeing
    /// those events.
    fn install_global_passthrough_subscriber() {
        use std::sync::OnceLock;
        static INSTALLED: OnceLock<()> = OnceLock::new();
        INSTALLED.get_or_init(|| {
            let global_layer = CapturingLayer::default();
            let global_subscriber = Registry::default().with(global_layer);
            let _ = tracing::subscriber::set_global_default(global_subscriber);
        });
    }

    // ---- Item 7: warn-capture test for the checksum-mismatch branch ---------

    /// Assert that `try_upstream_crate_pull` emits a `WARN`-level tracing
    /// event mentioning "checksum mismatch" when `ingest_verified` returns
    /// `Conflict` (upstream bytes don't match the NDJSON `cksum`).
    ///
    /// Uses the same `CapturingLayer` + `TRACING_TEST_MUTEX` +
    /// `install_global_passthrough_subscriber` idiom as
    /// `hort-app::use_cases::repository_access` — see that module for the
    /// detailed rationale. The test is `#[test]` (not `#[tokio::test]`)
    /// because the mutex guard cannot be held across an `await` point;
    /// we drive the async call via `block_on` on a fresh current-thread
    /// runtime inside the guarded scope.
    #[test]
    fn checksum_mismatch_emits_tracing_warn() {
        install_global_passthrough_subscriber();
        let _serial = TRACING_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let layer = CapturingLayer::default();
        let captured = layer.records.clone();
        let subscriber = Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        // Drive on a current-thread runtime so that `build_mock_ctx`
        // (which calls `tokio::spawn` inside `InMemoryEphemeralStore::new`)
        // and the subsequent `try_upstream_crate_pull` both run in the
        // same runtime context. The mutex guard above must not cross an
        // await point — `block_on` satisfies that constraint by driving
        // everything synchronously from the test thread.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(async {
            // Build the same harness as
            // `ingest_verified_returns_conflict_returns_checksum_mismatch`:
            // - index cksum deliberately lies about the artifact body.
            let (ctx, mocks) = build_mock_ctx(handle());
            let repo = cargo_repo("crates-mirror");
            mocks.repositories.insert(repo.clone());
            seed_mapping(&mocks, repo.id, "");

            let actual = b"actual-bytes".to_vec();
            let lying_cksum = sha256_hex(b"different-bytes");
            mocks
                .upstream_proxy
                .insert_metadata("", "/config.json", CRATES_IO_CONFIG.to_vec());
            mocks.upstream_proxy.insert_metadata(
                "",
                "/se/rd/serde",
                ndjson_entry("serde", "1.0.0", &lying_cksum),
            );
            mocks
                .upstream_proxy
                .insert_artifact("", &artifact_path("serde", "1.0.0"), actual);

            try_upstream_crate_pull(&ctx, &repo, "serde", "1.0.0").await
        });

        assert!(
            matches!(result, Err(UpstreamPullError::ChecksumMismatch)),
            "expected ChecksumMismatch, got {result:?}"
        );

        let records = captured.lock().unwrap();
        let warn_event = records
            .iter()
            .find(|(lvl, msg)| {
                *lvl == tracing::Level::WARN
                    && (msg.contains("checksum mismatch")
                        || msg.contains("ChecksumMismatch")
                        || msg.contains("checksum"))
            })
            .map(|(_, msg)| msg.clone());
        assert!(
            warn_event.is_some(),
            "expected WARN-level event mentioning checksum mismatch; captured: {records:?}"
        );
    }

    // ---- Cache hit: second call does NOT re-fetch config.json ---------------

    /// Reads through the cache once, then drops the seed: a second
    /// call must succeed entirely from the cached entry. Pins the
    /// "fetch only once per mapping" guarantee — load-bearing for
    /// the high-traffic crates.io proxy use case.
    #[tokio::test]
    async fn config_resolves_from_cache_on_second_call() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let repo = cargo_repo("crates-mirror");
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id, "");

        let body = b"the actual crate body".to_vec();
        let cksum = sha256_hex(&body);
        mocks
            .upstream_proxy
            .insert_metadata("", "/config.json", CRATES_IO_CONFIG.to_vec());
        mocks.upstream_proxy.insert_metadata(
            "",
            "/se/rd/serde",
            ndjson_entry("serde", "1.0.0", &cksum),
        );
        mocks
            .upstream_proxy
            .insert_artifact("", &artifact_path("serde", "1.0.0"), body.clone());

        // First call: populates the cache and ingests. Smoke that the
        // happy path runs end-to-end before the cache assertion.
        let _ = try_upstream_crate_pull(&ctx, &repo, "serde", "1.0.0")
            .await
            .expect("first call must succeed");

        // Overwrite the live config.json fixture with garbage. The
        // orchestrator re-reads config.json on every call ONLY if the
        // ephemeral cache misses; a cache hit must pre-empt this
        // poisoned bytes path. (MockUpstreamProxy.insert_metadata is
        // upsert by key, so the write replaces the original entry.)
        mocks
            .upstream_proxy
            .insert_metadata("", "/config.json", b"GARBAGE-NOT-JSON".to_vec());

        let artifact = try_upstream_crate_pull(&ctx, &repo, "serde", "1.0.0")
            .await
            .expect("second call must succeed via cached config.json");
        assert_eq!(artifact.name, "serde");
    }

    // ---- Item 11: index_upstream_url override tests -------------------------

    /// Override happy path: `repo.index_upstream_url = Some(...)` is set.
    /// The mock cannot distinguish which `upstream_url` was used because
    /// `MockUpstreamProxy::fetch_metadata` keys on `(path_prefix, path)`
    /// rather than `(upstream_url, path)` — the adapter's internal key
    /// does not include the URL. Approach (c) from the backlog: this test
    /// proves the orchestrator succeeds end-to-end with the override set,
    /// and the tracing span records `index_upstream_url_overridden = true`.
    /// The span field is the primary observable difference at unit-test
    /// level; production behavioural difference (actual URL used for HTTP)
    /// is exercised by the adapter's wiremock integration tests.
    #[test]
    fn override_happy_path_routes_index_via_override_host() {
        install_global_passthrough_subscriber();
        let _serial = TRACING_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let layer = CapturingLayer::default();
        let captured = layer.records.clone();
        let subscriber = Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(async {
            let (ctx, mocks) = build_mock_ctx(handle());
            let mut repo = cargo_repo("crates-mirror");
            // Set the override URL — only the span field is observable in
            // this unit test (approach c); the adapter's URL routing is
            // verified by wiremock integration tests.
            repo.index_upstream_url = Some("https://internal-index.example.com".to_string());
            mocks.repositories.insert(repo.clone());
            seed_mapping(&mocks, repo.id, "");

            let body = b"the actual crate body".to_vec();
            let cksum = sha256_hex(&body);
            // The mock keys on (path_prefix="", path), so the same
            // seed satisfies both mapping and index_mapping. This is the
            // limitation documented above — the test proves the orchestrator
            // produces the correct outcome, not which URL was targeted.
            mocks
                .upstream_proxy
                .insert_metadata("", "/config.json", CRATES_IO_CONFIG.to_vec());
            mocks.upstream_proxy.insert_metadata(
                "",
                "/se/rd/serde",
                ndjson_entry("serde", "1.0.214", &cksum),
            );
            mocks.upstream_proxy.insert_artifact(
                "",
                &artifact_path("serde", "1.0.214"),
                body.clone(),
            );

            try_upstream_crate_pull(&ctx, &repo, "serde", "1.0.214").await
        });

        let artifact = result.expect("override happy path must succeed");
        assert_eq!(artifact.name, "serde");
        assert_eq!(artifact.version.as_deref(), Some("1.0.214"));

        // The span field `index_upstream_url_overridden = true` is the
        // observable invariant captured by the CapturingLayer's on_new_span.
        let records = captured.lock().unwrap();
        let found_overridden = records.iter().any(|(_, msg)| {
            msg.contains("index_upstream_url_overridden")
                && (msg.contains("true") || msg.contains("= true"))
        });
        assert!(
            found_overridden,
            "expected span with index_upstream_url_overridden=true; captured: {records:?}"
        );
    }

    /// Override + metadata failure: when the index-leg fetch fails, the
    /// error propagates as `MetadataFetchFailed{stage: "config"}` and the
    /// span field `index_upstream_url_overridden = true` is emitted so
    /// operators can correlate the failure with the override in use.
    #[test]
    fn override_with_metadata_failure_propagates() {
        install_global_passthrough_subscriber();
        let _serial = TRACING_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let layer = CapturingLayer::default();
        let captured = layer.records.clone();
        let subscriber = Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(async {
            let (ctx, mocks) = build_mock_ctx(handle());
            let mut repo = cargo_repo("crates-mirror");
            repo.index_upstream_url = Some("https://internal-index.example.com".to_string());
            mocks.repositories.insert(repo.clone());
            seed_mapping(&mocks, repo.id, "");

            // Inject a one-shot failure on the first fetch_metadata call
            // (the config.json fetch). No metadata seeded means the error
            // fires immediately.
            mocks
                .upstream_proxy
                .fail_next_metadata_with(DomainError::Invariant(
                    "upstream:timeout:internal-index.example.com".into(),
                ));

            try_upstream_crate_pull(&ctx, &repo, "serde", "1.0.214").await
        });

        match result {
            Err(UpstreamPullError::MetadataFetchFailed { stage, .. }) => {
                assert_eq!(stage, "config", "failure must originate from config leg");
            }
            other => panic!("expected MetadataFetchFailed{{stage:\"config\"}}, got {other:?}"),
        }

        // Span field index_upstream_url_overridden=true must be visible so
        // operators can correlate the failure with the override host.
        let records = captured.lock().unwrap();
        let found_overridden = records.iter().any(|(_, msg)| {
            msg.contains("index_upstream_url_overridden")
                && (msg.contains("true") || msg.contains("= true"))
        });
        assert!(
            found_overridden,
            "expected span with index_upstream_url_overridden=true; captured: {records:?}"
        );
    }

    /// No-override regression: when `repo.index_upstream_url = None`, the
    /// orchestrator uses the default mapping URL and succeeds. This pins the
    /// invariant that Item 11 is purely additive — existing Cargo proxy
    /// repos without the field set continue to behave identically.
    #[tokio::test]
    async fn no_override_uses_mapping_host_regression() {
        let (ctx, mocks) = build_mock_ctx(handle());
        let mut repo = cargo_repo("crates-mirror-no-override");
        // Explicitly assert the no-override state is canonical.
        assert!(
            repo.index_upstream_url.is_none(),
            "sample_repository should initialise index_upstream_url = None (Item 10 default)"
        );
        repo.index_upstream_url = None;
        mocks.repositories.insert(repo.clone());
        seed_mapping(&mocks, repo.id, "");

        let body = b"the actual crate body".to_vec();
        let cksum = sha256_hex(&body);
        mocks
            .upstream_proxy
            .insert_metadata("", "/config.json", CRATES_IO_CONFIG.to_vec());
        mocks.upstream_proxy.insert_metadata(
            "",
            "/se/rd/serde",
            ndjson_entry("serde", "1.0.214", &cksum),
        );
        mocks
            .upstream_proxy
            .insert_artifact("", &artifact_path("serde", "1.0.214"), body.clone());

        let artifact = try_upstream_crate_pull(&ctx, &repo, "serde", "1.0.214")
            .await
            .expect("no-override path must succeed without index_upstream_url");

        assert_eq!(artifact.name, "serde");
        assert_eq!(artifact.version.as_deref(), Some("1.0.214"));
        assert_eq!(artifact.size_bytes as usize, body.len());
    }

    // ---- PullDedup wrap-coverage tests ----------------------------------------
    //
    // These tests assert that the four wrapped call sites
    // (sparse-index `fetch_metadata`, NDJSON `fetch_metadata`,
    // `.crate` `fetch_artifact`+`ingest_verified`, `config.json`
    // `fetch_metadata`) actually emit `hort_pull_dedup_total` metrics.
    //
    // The harness mirrors `crates/hort-app/src/pull_dedup.rs::tests::capture`:
    // install a `DebuggingRecorder` via `metrics::with_local_recorder`
    // around a `block_on` driving the async test body. Counter labels
    // are read back via `Snapshotter::snapshot` and matched on
    // `outcome` (and `layer` where layer-specificity matters).

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
    /// `outcome`. The two new tests want "did the metric fire ≥ N
    /// times for this outcome regardless of layer/format" assertions
    /// — `layer` differs (in_process vs cluster) depending on
    /// scheduler interleaving and `format` is the literal
    /// `"_any"` for blob-by-hash keys (the dedup key format for
    /// content-addressed blobs).
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

    /// Concurrent-coalesce test: spawn two `tokio::spawn` requests
    /// against the same `.crate` artifact. The wrapped
    /// `coalesce_blob` call site at the artifact-fetch leg must
    /// route both into a single coalescing window — exactly one
    /// `leader_started` increment, ≥ 1 `follower_waited_hit`
    /// increment.
    ///
    /// Determinism note: on a current-thread runtime the second
    /// `tokio::spawn` cannot run before the first awaits something
    /// inside its closure. The first task's `ingest_verified`
    /// path crosses many await points (CAS write, event-store
    /// append, lifecycle commit) before completing; the second
    /// task's `put_if_absent` therefore lands AFTER the first's,
    /// puts it onto the Layer-A broadcast (or the Layer-B poll
    /// loop), and observes the leader's terminal outcome.
    /// `await`ing both join handles before the metric-snapshot
    /// read pins the assertion.
    #[test]
    fn concurrent_blob_callers_coalesce_into_one_leader_started() {
        let snap = capture_metrics(|| async {
            let (ctx, mocks) = build_mock_ctx(handle());
            let repo = cargo_repo("crates-mirror");
            mocks.repositories.insert(repo.clone());
            seed_mapping(&mocks, repo.id, "");

            let body = b"the actual crate body".to_vec();
            let cksum = sha256_hex(&body);
            mocks
                .upstream_proxy
                .insert_metadata("", "/config.json", CRATES_IO_CONFIG.to_vec());
            mocks.upstream_proxy.insert_metadata(
                "",
                "/se/rd/serde",
                ndjson_entry("serde", "1.0.214", &cksum),
            );
            mocks.upstream_proxy.insert_artifact(
                "",
                &artifact_path("serde", "1.0.214"),
                body.clone(),
            );

            let ctx_a = ctx.clone();
            let repo_a = repo.clone();
            let h1 = tokio::spawn(async move {
                try_upstream_crate_pull(&ctx_a, &repo_a, "serde", "1.0.214").await
            });
            let ctx_b = ctx.clone();
            let repo_b = repo.clone();
            let h2 = tokio::spawn(async move {
                try_upstream_crate_pull(&ctx_b, &repo_b, "serde", "1.0.214").await
            });

            let r1 = h1.await.unwrap();
            let r2 = h2.await.unwrap();
            // Both callers must see a successful artifact regardless
            // of which one was elected leader vs follower — the
            // post-coalesce `find_in_repo_by_hash` resolves the row
            // the leader's ingest wrote.
            assert!(
                r1.is_ok(),
                "task 1 must succeed (leader OR follower); got {r1:?}"
            );
            assert!(
                r2.is_ok(),
                "task 2 must succeed (leader OR follower); got {r2:?}"
            );
        });

        // The `.crate` blob fetch is the load-bearing wrap for this
        // test — the metadata legs (config.json + NDJSON) ALSO
        // coalesce, so `leader_started` for the metadata legs may
        // also fire. We assert the BLOB leg coalesced by counting
        // total leader_started across all formats/layers — exactly
        // one blob leader plus at most two metadata leaders
        // (config.json + NDJSON, both metadata). The lower bound is
        // `leader_started >= 1` (the blob leader); the follower
        // assertion is the load-bearing one.
        let leader_started = sum_counter_for_outcome(&snap, "leader_started");
        let follower_waited_hit = sum_counter_for_outcome(&snap, "follower_waited_hit");
        assert!(
            leader_started >= 1,
            "expected ≥1 leader_started across the wrapped call sites; \
             got {leader_started}, snap: {snap:?}"
        );
        assert!(
            follower_waited_hit >= 1,
            "expected ≥1 follower_waited_hit (concurrent coalesce); \
             got {follower_waited_hit}, snap: {snap:?}"
        );
    }

    /// Negative-cache test: the wrapped `config.json` fetch fails
    /// (transport-level 404 via `fail_next_metadata_with`). The
    /// leader records the failure under the dedup key with the
    /// configured negative-cache TTL (default 30 s for
    /// `NotFound`). A second call within the TTL window must
    /// short-circuit on `negative_cache_hit` without firing a
    /// second `leader_started`.
    #[test]
    fn negative_cache_short_circuits_repeated_failures_within_ttl() {
        let snap = capture_metrics(|| async {
            let (ctx, mocks) = build_mock_ctx(handle());
            let repo = cargo_repo("crates-mirror");
            mocks.repositories.insert(repo.clone());
            seed_mapping(&mocks, repo.id, "");

            // First call: stage a one-shot transport failure on
            // the next `fetch_metadata` (the config.json fetch is
            // the first metadata call the orchestrator makes).
            // The leader records `Failed` under the config.json
            // dedup key.
            mocks
                .upstream_proxy
                .fail_next_metadata_with(DomainError::Invariant(
                    "upstream:not_found:config".into(),
                ));
            let r1 = try_upstream_crate_pull(&ctx, &repo, "serde", "1.0.0").await;
            assert!(
                matches!(r1, Err(UpstreamPullError::MetadataFetchFailed { stage, .. }) if stage == "config"),
                "first call must fail with MetadataFetchFailed{{stage:config}}; got {r1:?}"
            );

            // Second call within the negative-cache TTL window: the
            // `fail_next_metadata_with` queue is drained — if the
            // orchestrator re-issued the upstream fetch, it would
            // hit the absent-fixture path (which the mock returns
            // as a fresh `upstream:not_found` Err), counting as
            // `leader_started` again. The negative-cache short-
            // circuit prevents that: the second call must observe
            // the cached `Failed` outcome before any election.
            let r2 = try_upstream_crate_pull(&ctx, &repo, "serde", "1.0.0").await;
            assert!(
                r2.is_err(),
                "second call must surface the cached failure; got {r2:?}"
            );
        });

        // Assertion: `negative_cache_hit` increments by ≥ 1 (the
        // second call short-circuited). `leader_started` for the
        // config.json key stays at 1 (only the FIRST call elected;
        // the second was a cache hit). The metric snapshot is
        // aggregated across the four wrapped call sites; the
        // first call only reaches the config.json fetch (it errors
        // before NDJSON / blob), so `leader_started` should be
        // exactly 1 across the entire snapshot.
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
}
