//! PEP 658 `.metadata` endpoint handler
//! (see `docs/architecture/how-to/pypi-pull-through.md`).
//!
//! Serves the wheel's `<dist-info>/METADATA` bytes (cached at
//! ingest time) over
//! `GET /{repo_key}/files/{filename}.metadata` — which in hort's PyPI
//! route shape is `/pypi/{repo_key}/simple/{project}/{filename}.metadata`
//! (the wheel-download route slot, suffix-branched in `lib.rs::download`).
//!
//! # Dispatch
//!
//! - **sdist path** (filename does NOT end in `.whl`) → 404. PEP 658
//!   applies only to wheels (PEP 658 §"Specification").
//! - **wheel path with hosted/staging/virtual repo** → delegate to
//!   [`WheelMetadataUseCase::serve`]. Returns 200 + bytes +
//!   `Content-Digest` on success; 404 on Rejected /
//!   ScanIndeterminate / un-backfilled / invisible / missing
//!   (anti-enumeration); 503 + `Retry-After` on Quarantined.
//! - **wheel path with proxy repo** → strategy-2 dispatch:
//!   1. Call [`WheelMetadataUseCase::serve`] (the hosted path). On
//!      success — wheel was already in CAS AND the `wheel_metadata`
//!      ContentReference row was present (ingest hook ran during a
//!      previous pull-through) — render the response and return.
//!   2. On `NotFound { entity: "Artifact" }`, re-resolve the artifact
//!      via [`ArtifactUseCase::find_visible_by_path`] to disambiguate
//!      "wheel not in CAS" (cache miss) from "wheel in CAS but no
//!      ContentReference row" (legacy wheel or extract returned `None`).
//!      - **Legacy / no-metadata row** → 404. Operator runs the
//!        `wheel-metadata-backfill` task to populate; no implicit
//!        on-the-fly extract on the read path.
//!      - **Cache miss** → trigger the existing
//!        [`crate::upstream_pull::try_upstream_file_pull`] orchestrator.
//!        The ingest hook fires automatically inside
//!        `IngestUseCase::ingest_verified` — the wheel METADATA bytes
//!        land in CAS + `wheel_metadata` ContentReference by
//!        construction. Re-serve via the hosted path.
//!   3. Concurrent `.metadata` requests for the same wheel on cache
//!      miss single-flight on the EXISTING wheel-pull dedup keys
//!      ([`DedupKey::metadata`] for the JSON leg and
//!      [`DedupKey::blob_by_hash`] for the wheel leg) — both keyed on
//!      the wheel itself, both already exercised by
//!      `concurrent_blob_callers_coalesce_into_one_leader_started`
//!      in `upstream_pull.rs`. No new `DedupKey::MetadataFile` variant
//!      is needed because the strategy-2 dispatch converges N
//!      concurrent metadata requests onto the same wheel pull.
//!
//! # Why strategy-2 (full-wheel pull) for proxy cache-miss
//!
//! Two strategies were considered for proxy cache-miss:
//! strategy 1 (direct upstream `<wheel>.metadata` fetch with an
//! orphan-key placeholder ContentReference) and strategy 2 (full-wheel
//! pull + extract via [`IngestUseCase::ingest_verified`]). Strategy 2
//! was chosen because:
//!
//! - Zero schema changes (the `content_references.source_artifact_id`
//!   stays NOT NULL with FK to `artifacts(id)` ON DELETE CASCADE;
//!   strategy 1 would have required either a schema change or a
//!   synthetic placeholder artifact row).
//! - Always correct: works even when upstream lacks PEP 658.
//! - One code path per cache-miss.
//!
//! Tradeoff: the first `.metadata` request on a cache-miss proxy
//! pulls the full wheel (~1–100 MB) instead of just the metadata
//! (~1–10 KB); the bandwidth saving only kicks in on the second+
//! request when the wheel is already cached.
//!
//! # Why the dispatch lives in the handler (not the use case)
//!
//! The "use case sees the `RepositoryType` and decides" shape would
//! require [`WheelMetadataUseCase`] to invoke
//! [`crate::upstream_pull::try_upstream_file_pull`] on cache-miss —
//! but `try_upstream_file_pull` lives in `hort-http-pypi` (the inbound-
//! HTTP adapter), and `hort-app` cannot depend on `hort-http-pypi`
//! (the dep graph is unidirectional per ADR 0008: HTTP crates depend on
//! `hort-app`, not the other way around). The only ways to put the
//! dispatch in the use case would be (1) a new outbound port for
//! "trigger upstream wheel pull" (heavyweight, mirrors zero existing
//! pulls through a port), or (2) a callback/closure threaded into the
//! use case (extra indirection with no architectural benefit). The
//! handler-side dispatch matches the codebase precedent in
//! [`crate::download`] (PyPI cache-miss already orchestrates
//! upstream pull at the handler level, not in the use case).
//!
//! # Response shape (200 path)
//!
//! - `Content-Type: text/plain; charset=utf-8` (PEP 658 spec).
//! - `Content-Length: <bytes>` — always set, even for zero-length
//!   payloads (mirrors the wheel-download anti-truncation discipline).
//! - `Content-Digest: sha256=:<base64>:` per RFC 9530, carrying the
//!   ContentReference's `target_content_hash` so a tampering proxy on
//!   the wire is client-detectable.
//! - Body streams from CAS — no buffering.

use std::sync::Arc;

use axum::body::Body;
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::StatusCode;
use axum::response::Response;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use chrono::Utc;

use hort_app::error::AppError;
use hort_app::use_cases::wheel_metadata_use_case::{MetadataBlob, WheelMetadataServeOutcome};
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::entities::repository::RepositoryType;
use hort_domain::error::DomainError;
use hort_domain::types::ContentHash;
use hort_http_core::body::{stream_blob, DEFAULT_STREAM_CAPACITY};
use hort_http_core::context::AppContext;
use hort_http_core::error::ApiError;

/// Serve a PEP 658 `.metadata` request for `(repo_key, project, wheel_filename)`.
///
/// `wheel_filename` is the **wheel filename without the `.metadata`
/// suffix** (e.g. `example-1.0.0-py3-none-any.whl`); the HTTP handler
/// in `lib.rs::download` does the suffix stripping before calling
/// this helper.
///
/// This dispatcher resolves the repo's `RepositoryType` first so a
/// proxy repo's `.metadata` routes through the strategy-2
/// cache-miss-via-pull-through dispatch (see module doc). Hosted /
/// Staging / Virtual repos call through to
/// [`WheelMetadataUseCase::serve`] directly.
pub(crate) async fn serve_pep658_metadata(
    ctx: Arc<AppContext>,
    repo_key: String,
    project: String,
    wheel_filename: String,
    actor: Option<&CallerPrincipal>,
) -> Result<Response, ApiError> {
    // (a) Visibility-gated repo resolution FIRST. This is the
    // anti-enumeration gate — an invisible private repo must yield the
    // canonical `Repository NotFound` envelope, byte-identical to a
    // missing-repo response. Performing the sdist suffix-check
    // BEFORE this hop would leak whether a `.tar.gz.metadata` URL was
    // an "unsupported-extension" reject vs an "invisible-repo" reject
    // (different envelopes), breaking the anti-enumeration property
    // the matching wheel branch enforces. Same hop the wheel-download
    // handler runs.
    let repo = ctx
        .repository_access_use_case
        .resolve(
            &repo_key,
            actor,
            hort_app::use_cases::repository_access::AccessLevel::Read,
        )
        .await
        .map_err(ApiError::from)?;

    // (b) Sdist path → 404. PEP 658 applies only to wheels (PEP 658
    // §"Specification"). After the visibility check above, an invisible repo
    // has already produced a `Repository NotFound` — so by the time we
    // reach this check, the caller is known to have Read on the repo
    // (or auth is disabled). A sdist `.metadata` returns
    // `Artifact NotFound` indistinguishably from "missing wheel" on a
    // visible repo — both are the operator-visible no-such-resource
    // envelope.
    if !wheel_filename.ends_with(".whl") {
        return Err(ApiError::from(AppError::Domain(DomainError::NotFound {
            entity: "Artifact",
            id: format!("{repo_key}:simple/{project}/{wheel_filename}.metadata"),
        })));
    }

    let artifact_path = format!("simple/{project}/{wheel_filename}");

    if matches!(repo.repo_type, RepositoryType::Proxy) {
        return serve_proxy_with_pull_fallback(
            ctx,
            repo,
            repo_key,
            project,
            wheel_filename,
            artifact_path,
            actor,
        )
        .await;
    }

    // (c) Hosted/Staging/Virtual — call through to the use case.
    // The use case re-runs the visibility hop (defence in depth).
    let outcome = ctx
        .wheel_metadata_use_case
        .serve(&repo_key, &artifact_path, actor)
        .await
        .map_err(ApiError::from)?;

    match outcome {
        WheelMetadataServeOutcome::Available(blob) => Ok(build_metadata_response(blob)),
        WheelMetadataServeOutcome::Quarantined {
            quarantine_deadline,
        } => Ok(build_quarantined_response(quarantine_deadline)),
    }
}

/// Strategy-2 proxy cache-miss dispatch for the PEP 658 `.metadata`
/// endpoint. See module doc for the design rationale (strategy 1 dropped).
///
/// Algorithm:
///
/// 1. Try the hosted-style serve via [`WheelMetadataUseCase::serve`].
///    Cache hit (wheel in CAS + ContentReference present, ingest hook
///    ran during a previous pull-through) → render the response and return.
/// 2. On `NotFound { entity: "Artifact" }`, disambiguate "wheel not
///    in CAS" (real cache miss) vs "wheel in CAS but no
///    ContentReference row" (legacy wheel or the ingest hook
///    saw `extract_wheel_metadata_bytes` return `None`):
///    - `find_visible_by_path` returns `Ok(artifact)` → 404, do NOT
///      pull. Operator runs the backfill task.
///    - `find_visible_by_path` returns `NotFound { entity:
///      "Artifact" }` → trigger
///      [`crate::upstream_pull::try_upstream_file_pull`]. The
///      ingest hook fires automatically; on success, re-serve via the
///      hosted path.
///
/// `#[tracing::instrument]` is added without `err` (per the architect
/// skill's observability rules — `err` would re-log the `ApiError`
/// chain at `error` level, duplicating the call-site logging the
/// handler's own `ApiError` mapping does).
#[tracing::instrument(
    skip(ctx, actor),
    fields(repo_key = %repo_key, wheel_filename = %wheel_filename),
)]
async fn serve_proxy_with_pull_fallback(
    ctx: Arc<AppContext>,
    repo: hort_domain::entities::repository::Repository,
    repo_key: String,
    project: String,
    wheel_filename: String,
    artifact_path: String,
    actor: Option<&CallerPrincipal>,
) -> Result<Response, ApiError> {
    // (1) Try the hosted-style serve first.
    let first_attempt = ctx
        .wheel_metadata_use_case
        .serve(&repo_key, &artifact_path, actor)
        .await;

    match first_attempt {
        Ok(outcome) => {
            tracing::debug!("proxy .metadata cache hit — serving from CAS without pull-through");
            return Ok(render_outcome(outcome));
        }
        Err(AppError::Domain(DomainError::NotFound {
            entity: "Artifact", ..
        })) => { /* fall through to disambiguation */ }
        Err(other) => return Err(other.into()),
    }

    // (2a) Disambiguate cache-miss vs legacy un-backfilled wheel.
    match ctx
        .artifact_use_case
        .find_visible_by_path(&repo_key, &artifact_path, actor)
        .await
    {
        Ok((_repo, _artifact)) => {
            // Wheel IS in CAS — the missing-ContentReference branch.
            // Quarantined / Rejected / ScanIndeterminate also fall
            // here (the use case maps them onto NotFound), and the
            // first-attempt outcome for Quarantined would already
            // have been `Quarantined` — so by elimination this arm
            // is the legacy-no-metadata-row case (or Rejected /
            // ScanIndeterminate which we collapse to 404 anyway per
            // all collapse to 404).
            tracing::debug!(
                "proxy .metadata 404 — wheel in CAS but no wheel_metadata row \
                 (legacy ingest or extract returned None); \
                 operator runs the wheel-metadata-backfill task to populate"
            );
            Err(ApiError::from(AppError::Domain(DomainError::NotFound {
                entity: "Artifact",
                id: format!("{repo_key}:{artifact_path}.metadata"),
            })))
        }
        Err(AppError::Domain(DomainError::NotFound {
            entity: "Artifact", ..
        })) => {
            // (2b) Real cache miss — trigger pull-through.
            tracing::info!(
                "proxy .metadata cache miss — triggering wheel pull-through; \
                 the ingest hook will extract + persist METADATA into CAS"
            );
            match crate::upstream_pull::try_upstream_file_pull(
                &ctx,
                &repo,
                &project,
                &wheel_filename,
            )
            .await
            {
                Ok(_artifact) => {
                    // Re-serve via the hosted path now that the wheel
                    // (and, by the ingest hook, the wheel_metadata
                    // ContentReference) is in CAS.
                    let outcome = ctx
                        .wheel_metadata_use_case
                        .serve(&repo_key, &artifact_path, actor)
                        .await
                        .map_err(ApiError::from)?;
                    Ok(render_outcome(outcome))
                }
                // Pull-through failed — render the same wire shape the
                // wheel-download handler does for the equivalent
                // failure (checksum mismatch → 502 + X-Hort-Reason,
                // missing upstream → 404, etc.). Reuses the existing
                // `map_upstream_pull_error` so the envelope stays
                // identical between `.metadata` and the wheel itself.
                Err(e) => Ok(crate::upstream_pull::map_upstream_pull_error(&e)),
            }
        }
        // Repository visibility / other errors propagate. The first
        // `serve` call already passed the visibility check, so a `Repository`
        // NotFound here would indicate a race (repo deleted between
        // the two calls) — surface it indistinguishably from the
        // initial visibility check.
        Err(other) => Err(other.into()),
    }
}

/// Render a [`WheelMetadataServeOutcome`] into a wire response. Shared
/// between the hosted-path serve and the strategy-2 proxy re-serve so
/// the `Content-Digest` / `Content-Length` / `Retry-After` discipline
/// stays identical between the two.
fn render_outcome(outcome: WheelMetadataServeOutcome) -> Response {
    match outcome {
        WheelMetadataServeOutcome::Available(blob) => build_metadata_response(blob),
        WheelMetadataServeOutcome::Quarantined {
            quarantine_deadline,
        } => build_quarantined_response(quarantine_deadline),
    }
}

/// Build the 200 response from a [`MetadataBlob`]. Mirrors the
/// wheel-download handler's header discipline (always emits
/// `Content-Length`, never falls back to chunked encoding).
fn build_metadata_response(blob: MetadataBlob) -> Response {
    let MetadataBlob {
        bytes,
        content_hash,
        size,
    } = blob;
    let body = stream_blob(bytes, DEFAULT_STREAM_CAPACITY);
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(CONTENT_LENGTH, size)
        .header(
            "Content-Digest",
            format_content_digest_sha256(&content_hash),
        )
        .body(body)
        .expect("static-shape headers + streamed body always builds")
}

/// Build the 503 response for a quarantined parent wheel. Mirrors the
/// wheel-download handler's `Retry-After` shape exactly — including
/// the fall-back to a 1-hour string when no deadline is hydrated.
fn build_quarantined_response(quarantine_deadline: Option<chrono::DateTime<Utc>>) -> Response {
    let retry_after = quarantine_deadline
        .map(|deadline| {
            let secs = (deadline - Utc::now()).num_seconds().max(1);
            secs.to_string()
        })
        .unwrap_or_else(|| "3600".to_string());
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header("Retry-After", retry_after)
        .body(Body::from(
            serde_json::json!({"error": "artifact is quarantined"}).to_string(),
        ))
        .expect("static-shape quarantined response always builds")
}

/// Format a [`ContentHash`] into an RFC 9530 `Content-Digest` header
/// value: `sha256=:<base64-of-raw-32-bytes>:`.
///
/// The header semantics (RFC 9530 §3) are:
/// `sha256=` is the algorithm token, the value between colons is a
/// Structured-Fields byte sequence — base64-encoded 32 raw SHA-256
/// bytes. Standard base64 (RFC 4648 §4) with `=` padding retained.
///
/// We decode `ContentHash`'s 64-char lowercase hex form to raw bytes
/// first, then base64-encode. The function is infallible on a valid
/// `ContentHash` (the type guarantees 64 lowercase hex chars at
/// construction); the `unreachable!` arm exists for the type-system
/// path only.
pub(crate) fn format_content_digest_sha256(hash: &ContentHash) -> String {
    let hex = hash.as_ref();
    debug_assert_eq!(hex.len(), 64, "ContentHash invariant: 64 hex chars");
    let mut raw = [0u8; 32];
    for (i, byte) in raw.iter_mut().enumerate() {
        let hi = hex_value(hex.as_bytes()[i * 2]);
        let lo = hex_value(hex.as_bytes()[i * 2 + 1]);
        *byte = hi * 16 + lo;
    }
    let b64 = BASE64_STANDARD.encode(raw);
    format!("sha256=:{b64}:")
}

/// Convert one lowercase ASCII hex digit byte → 0..16. The `ContentHash`
/// constructor enforces lowercase hex, so any other byte is an invariant
/// violation we surface via debug_assert + a defined-default 0 in
/// release.
fn hex_value(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        _ => {
            debug_assert!(false, "ContentHash invariant: lowercase hex only");
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build the canonical `Content-Digest` header value for the
    /// SHA-256 of the empty input (`e3b0c4...b855`) — one of the most
    /// stable test vectors in the universe. Pins the format string
    /// against any accidental refactor.
    #[test]
    fn content_digest_format_matches_rfc9530_for_empty_sha256() {
        let hash: ContentHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            .parse()
            .unwrap();
        let header = format_content_digest_sha256(&hash);
        // The empty SHA-256 base64-encoded raw bytes: 47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
        assert_eq!(
            header,
            "sha256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"
        );
    }

    /// Computed SHA-256 of a non-empty body round-trips through the
    /// `Content-Digest` header → base64-decode → hex pipeline back to
    /// the original hash. Catches any byte-swapping bug in the
    /// `hex_value` / pack loop that the empty-input vector (every byte
    /// distinct) doesn't exercise.
    #[test]
    fn content_digest_format_round_trips_through_base64_back_to_hex() {
        use sha2::{Digest, Sha256};
        let payload = b"Metadata-Version: 2.1\nName: example\nVersion: 1.0.0\n";
        let mut h = Sha256::new();
        h.update(payload);
        let hex = format!("{:x}", h.finalize());
        let hash: ContentHash = hex.parse().unwrap();
        let header = format_content_digest_sha256(&hash);
        // Structural shape: `sha256=:` + 44 base64 chars + `:`.
        assert!(header.starts_with("sha256=:"), "wrong prefix: {header}");
        assert!(header.ends_with(':'), "wrong suffix: {header}");
        // 32 raw bytes → 44-char base64 with `=` padding.
        let inner = header
            .strip_prefix("sha256=:")
            .and_then(|s| s.strip_suffix(':'))
            .expect("strip prefix+suffix");
        assert_eq!(inner.len(), 44, "wrong base64 length: {inner}");
        // Round-trip: base64-decode the header value, hex-encode, compare
        // to the original ContentHash hex.
        let raw = BASE64_STANDARD.decode(inner).expect("valid base64");
        let round_trip_hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(round_trip_hex, hex);
    }

    /// Sanity check: every byte position in the hex string maps to the
    /// expected nibble. Catches half-byte-swap bugs.
    #[test]
    fn hex_value_decodes_each_digit_class_correctly() {
        for (byte, expected) in [
            (b'0', 0),
            (b'5', 5),
            (b'9', 9),
            (b'a', 10),
            (b'c', 12),
            (b'f', 15),
        ] {
            assert_eq!(hex_value(byte), expected, "hex {byte:#x}");
        }
    }
}
