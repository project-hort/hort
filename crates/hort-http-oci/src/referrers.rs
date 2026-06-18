//! OCI Referrers API — `GET /v2/<name>/referrers/<digest>`.
//!
//! Spec: OCI Distribution Spec v1.1 §referrers-api.
//! Proxy referrer fetch: ADR 0027.
//!
//! # Read path
//!
//! 1. Resolve `repo_key` via `ctx.repositories`. Missing → `NAME_UNKNOWN`.
//! 2. Parse `digest_str` into a [`ContentHash`]. Malformed → 400
//!    `DIGEST_INVALID`; well-formed-but-unsupported (e.g. `sha512:`) →
//!    400 `UNSUPPORTED`.
//! 3. Call [`ContentReferenceIndex::find_by_target`] with `kind_filter =
//!    Some("oci_subject")` so the SQL predicate excludes other reference
//!    kinds at the adapter boundary.
//! 4. Apply the `?artifactType=` filter as a post-query check on each
//!    row's `metadata.artifact_type`. The port itself is not aware of
//!    OCI semantics; the filter lives here.
//! 5. For each kept row, resolve the source artifact via
//!    [`ArtifactRepository::find_by_id`] to recover `sha256` + `size`.
//!    Tombstoned source rows (NotFound) are skipped silently — the
//!    referrers index is eventual; the artifact-DELETE path's
//!    `delete_by_source` call eventually clears them.
//! 6. Return an OCI image-index document
//!    (`application/vnd.oci.image.index.v1+json`) with one descriptor
//!    per surviving row.
//!
//! # Empty results return 200, NOT 404
//!
//! The OCI spec is explicit: an unknown subject — never pushed, or
//! filtered out by `?artifactType=` — returns 200 with `manifests: []`.
//! A 404 here would create an enumeration oracle (the subject's
//! existence becomes inferrable from the response shape). The first
//! TDD test in this module pins that behaviour against regression.
//!
//! # Metric
//!
//! Every call increments `hort_content_reference_queries_total{format =
//! "oci", repository, result}` once. `result` values:
//!
//! - `success` — the handler emitted a 200 response (whether the body
//!   listed zero or many manifests).
//! - `not_found` — repository lookup returned `DomainError::NotFound`.
//! - `digest_invalid` — `digest_str` failed to parse (malformed or
//!   well-formed-but-unsupported algorithm).
//! - `error` — any other infrastructure failure (repo-lookup transient
//!   error, content-reference port error).

use std::sync::Arc;

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use hort_app::error::AppError;
use hort_app::use_cases::repository_access::AccessLevel;
use hort_domain::entities::caller::CallerPrincipal;
use hort_domain::error::DomainError;
use hort_domain::ports::content_reference_index::ContentReference;
use hort_domain::types::ContentHash;

use super::digest::{parse_digest, DigestParse};
use super::error::OciError;
use hort_http_core::context::AppContext;

/// OCI image-index media type used as the response `Content-Type` and
/// the `mediaType` field on the response body itself.
const IMAGE_INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";

/// Default `mediaType` echoed back per descriptor when the row's
/// `metadata.media_type` field is missing or null. Matches the OCI v1
/// single-image manifest type — the same fallback the manifest pull
/// path uses.
const DEFAULT_DESCRIPTOR_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

/// Serve the referrers list for `(repo_key, name, digest_str)`.
///
/// Public so the dispatch in [`super::lib`]'s `dispatch` function can
/// call it with the already-split `name` / `digest_str` from
/// `TailKind::Referrers`. Per the OCI spec, the response is a 200 with
/// an empty `manifests` array even when no referring manifest exists —
/// 404 is reserved for an unknown repository.
///
/// `#[tracing::instrument]` covers the multi-step fan-out (one
/// `find_by_target` query plus N `find_by_id` lookups). `err` is
/// deliberately omitted: the handler returns 200 + `manifests: []` for
/// the common "unknown subject" case and 4xx envelopes for client
/// errors — none of those should log at ERROR. Operator-level
/// `tracing::error!` calls inside the function still surface true
/// infrastructure failures.
#[tracing::instrument(
    skip(ctx),
    fields(repo_key = %repo_key, digest = %digest_str, artifact_type = ?artifact_type_filter)
)]
pub async fn serve(
    ctx: Arc<AppContext>,
    repo_key: &str,
    name: &str,
    digest_str: &str,
    artifact_type_filter: Option<&str>,
    actor: Option<&CallerPrincipal>,
) -> Response {
    // 1. Resolve + visibility-check the repository through the new
    //    use case. Missing OR invisible-to-actor
    //    private repo collapse to NAME_UNKNOWN (anti-enumeration);
    //    transient errors → 500 INTERNAL so an operator who collapses
    //    the DB doesn't see 404s on every request.
    let repo = match ctx
        .repository_access_use_case
        .resolve(repo_key, actor, AccessLevel::Read)
        .await
    {
        Ok(r) => r,
        Err(AppError::Domain(DomainError::NotFound { .. })) => {
            // The request URL's `repo_key` may be syntactically valid
            // but doesn't resolve to a visible row. Use the `unknown`
            // sentinel here (subject to the toggle) so a flood of
            // made-up or invisible-private keys can't inflate the
            // metric series cardinality. The HTTP response still
            // carries the requested key in the OCI envelope.
            emit_metric(&repo_label(&ctx, None), "not_found");
            return OciError::NameUnknown {
                repository: repo_key.to_string(),
            }
            .into_response();
        }
        Err(e) => {
            tracing::error!(
                repo_key = %repo_key,
                error = %e,
                "repo lookup failed during OCI referrers query"
            );
            // Same treatment as `not_found`: no resolved row → use the
            // `unknown` sentinel (collapses to `_all` when the toggle
            // is off).
            emit_metric(&repo_label(&ctx, None), "error");
            return OciError::Internal.into_response();
        }
    };

    // 2. Parse the path digest. Malformed → DIGEST_INVALID; non-sha256
    //    well-formed → UNSUPPORTED. Both surface as 400 but on
    //    different OCI codes.
    let target_hash: ContentHash = match parse_digest(digest_str) {
        DigestParse::Ok(h) => h,
        DigestParse::Unsupported { algorithm } => {
            emit_metric(&repo_label(&ctx, Some(&repo.key)), "digest_invalid");
            return OciError::Unsupported {
                message: format!("unsupported digest algorithm: {algorithm}"),
            }
            .into_response();
        }
        DigestParse::Invalid { message } => {
            emit_metric(&repo_label(&ctx, Some(&repo.key)), "digest_invalid");
            return OciError::DigestInvalid { message }.into_response();
        }
    };

    // 3. Look up every reference whose target equals this digest, with
    //    the kind filter pinned at the SQL boundary so cross-`kind`
    //    rows never leak into the OCI response.
    //
    //    Routed through `ContentReferenceUseCase` (ADR 0008). The use
    //    case re-runs the visibility check internally; the redundant
    //    resolve is by design — keeping the explicit step-1 `resolve`
    //    above preserves error-precedence (NAME_UNKNOWN before
    //    DIGEST_INVALID when both are wrong) and gives the handler a
    //    clean place to emit the `not_found` metric. The repo handle
    //    returned by `find_by_visible_target` is discarded because
    //    step-1's `repo` is already in scope.
    let rows = match ctx
        .content_reference_use_case
        .find_by_visible_target(repo_key, &target_hash, Some("oci_subject"), actor)
        .await
    {
        Ok((_repo, r)) => r,
        Err(AppError::Domain(DomainError::NotFound { .. })) => {
            // Defensive: the step-1 resolve above already drained the
            // visibility-miss path, so this branch only fires under a
            // race where the repo was deleted between our two calls.
            // Treat the same as the original step-1 NotFound mapping.
            emit_metric(&repo_label(&ctx, Some(&repo.key)), "not_found");
            return OciError::NameUnknown {
                repository: repo_key.to_string(),
            }
            .into_response();
        }
        Err(e) => {
            tracing::error!(
                repo_key = %repo_key,
                error = %e,
                "content_references.find_by_target failed during OCI referrers query"
            );
            emit_metric(&repo_label(&ctx, Some(&repo.key)), "error");
            return OciError::Internal.into_response();
        }
    };

    // 4. Optional `?artifactType=` post-filter on `metadata.artifact_type`.
    //    `None` passes everything through; `Some(t)` keeps only rows
    //    whose metadata field equals `t`. A row whose
    //    `metadata.artifact_type` is missing / null is dropped under a
    //    `Some(_)` filter (the client asked for a specific type and
    //    the row has none). An unknown filter value still returns 200
    //    with an empty list — never 404.
    let filtered: Vec<&ContentReference> = rows
        .iter()
        .filter(|row| match artifact_type_filter {
            None => true,
            Some(t) => row
                .metadata
                .get("artifact_type")
                .and_then(|v| v.as_str())
                .map(|s| s == t)
                .unwrap_or(false),
        })
        .collect();

    // 5. For each surviving row, resolve the source artifact for its
    //    sha256 + size. Tombstoned sources (NotFound) drop silently —
    //    the index is eventual and the artifact-DELETE path's
    //    `delete_by_source` is the authoritative cleanup.  Other
    //    errors (transient DB) abort the whole request as 500 because
    //    a partial response would silently misrepresent "what
    //    references this digest".
    let mut manifests: Vec<serde_json::Value> = Vec::new();
    for row in filtered {
        // Visibility-aware row hydration (ADR 0008). Repo visibility was
        // already proved at step 1; routing through `find_visible_by_id`
        // keeps the call shape uniform across the crate. A tombstoned
        // source surfaces as `Artifact NotFound`, dropped silently.
        let (_repo, artifact) = match ctx
            .artifact_use_case
            .find_visible_by_id(row.source_artifact_id, actor)
            .await
        {
            Ok(t) => t,
            Err(AppError::Domain(DomainError::NotFound { .. })) => {
                tracing::debug!(
                    source_artifact_id = %row.source_artifact_id,
                    "referrers row points at a tombstoned (or invisible) artifact; skipping"
                );
                continue;
            }
            Err(e) => {
                tracing::error!(
                    source_artifact_id = %row.source_artifact_id,
                    error = %e,
                    "artifact lookup failed during referrers projection"
                );
                emit_metric(&repo_label(&ctx, Some(&repo.key)), "error");
                return OciError::Internal.into_response();
            }
        };

        let media_type = row
            .metadata
            .get("media_type")
            .and_then(|v| v.as_str())
            .unwrap_or(DEFAULT_DESCRIPTOR_MEDIA_TYPE)
            .to_string();

        let mut descriptor = serde_json::json!({
            "mediaType": media_type,
            "digest": format!("sha256:{}", artifact.sha256_checksum.as_ref()),
            "size": artifact.size_bytes,
        });

        // Echo `artifactType` only when the metadata row supplied a
        // non-null value. Spec §referrers-api permits the field to be
        // omitted when the source manifest had no `artifactType`.
        if let Some(at) = row.metadata.get("artifact_type").and_then(|v| v.as_str()) {
            descriptor
                .as_object_mut()
                .expect("descriptor is a JSON object by construction")
                .insert(
                    "artifactType".to_string(),
                    serde_json::Value::String(at.to_string()),
                );
        }

        manifests.push(descriptor);
    }

    // 6. Build the OCI image-index envelope. Empty `manifests` is the
    //    spec-mandated shape for "no referrers" — NOT 404.
    let body = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": IMAGE_INDEX_MEDIA_TYPE,
        "manifests": manifests,
    });
    // The OCI referrers response is spec-mandated NOT to echo `name` in
    // the image-index body, so dropping it here is correct. The handler
    // keeps the parameter because future pagination / Link-header work
    // may need it.
    let _ = name;

    emit_metric(&repo_label(&ctx, Some(&repo.key)), "success");

    let bytes = serde_json::to_vec(&body)
        .expect("OCI image-index envelope serialises to JSON without failure");
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static(IMAGE_INDEX_MEDIA_TYPE),
    );
    (StatusCode::OK, headers, Body::from(bytes)).into_response()
}

/// Resolve the `repository` metric label per the workspace-wide
/// `METRICS_INCLUDE_REPOSITORY_LABEL` toggle.
///
/// Mirrors the rule documented in `docs/metrics-catalog.md`:
///
/// - Toggle off → [`hort_app::metrics::values::REPOSITORY_ALL`] (`"_all"`)
///   collapses every series into a single line, regardless of which
///   repo or whether the lookup succeeded. Same shape as
///   [`super::upload_session::resolve_repo_label`] uses; centralising
///   the toggle check here avoids drift between the two emitters.
/// - Toggle on, `key = Some(k)` → emit `k` verbatim. Cardinality is
///   bounded by the operator-controlled set of repository keys.
/// - Toggle on, `key = None` → emit
///   [`hort_app::metrics::values::REPOSITORY_UNKNOWN`] (`"unknown"`).
///   Used when the repository lookup itself failed (NotFound or
///   transient error): the request URL's `repo_key` may be valid
///   syntax but doesn't resolve to a row, and emitting an unbounded
///   set of made-up keys would defeat the cardinality bound the
///   toggle exists to enforce.
///
/// Synchronous (no DB roundtrip) because every caller already has the
/// repo resolved or knows the lookup failed; the async variant in
/// [`super::upload_session::resolve_repo_label`] exists for sites that
/// only have a `repo_id` and is intentionally distinct.
fn repo_label(ctx: &AppContext, key: Option<&str>) -> String {
    if !ctx.include_repository_label {
        return hort_app::metrics::values::REPOSITORY_ALL.to_string();
    }
    match key {
        Some(k) => k.to_string(),
        None => hort_app::metrics::values::REPOSITORY_UNKNOWN.to_string(),
    }
}

/// Emit `hort_content_reference_queries_total{format="oci", repository,
/// result}` once per call. Centralised so every exit path in [`serve`]
/// fires exactly one counter increment with the matching `result`
/// label. The `repository` value is pre-resolved by [`repo_label`] —
/// callers MUST funnel through that helper so the
/// `METRICS_INCLUDE_REPOSITORY_LABEL` toggle is honoured at every exit.
fn emit_metric(repository: &str, result: &str) {
    metrics::counter!(
        "hort_content_reference_queries_total",
        "format" => "oci",
        "repository" => repository.to_string(),
        "result" => result.to_string(),
    )
    .increment(1);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::Utc;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshot};
    use metrics_util::{CompositeKey, MetricKind};
    use uuid::Uuid;

    use hort_app::use_cases::test_support::{
        sample_artifact, sample_repository, MockArtifactRepository, MockContentReferenceIndex,
        MockRepositoryRepository,
    };
    use hort_domain::entities::artifact::QuarantineStatus;
    use hort_domain::entities::repository::{Repository, RepositoryFormat};
    use hort_domain::ports::content_reference_index::ContentReference;

    use hort_http_core::test_support::build_mock_ctx;

    // -------------------- Harness --------------------

    struct Harness {
        ctx: Arc<AppContext>,
        artifacts: Arc<MockArtifactRepository>,
        repositories: Arc<MockRepositoryRepository>,
        content_references: Arc<MockContentReferenceIndex>,
    }

    fn harness() -> Harness {
        let handle = PrometheusBuilder::new().build_recorder().handle();
        let (ctx, mocks) = build_mock_ctx(handle);
        Harness {
            ctx,
            artifacts: mocks.artifacts,
            repositories: mocks.repositories,
            content_references: mocks.content_references,
        }
    }

    fn oci_repo(key: &str) -> Repository {
        let mut r = sample_repository();
        r.key = key.into();
        r.format = RepositoryFormat::Oci;
        r
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

    // A valid sha256 hex value used as the path digest in tests.
    const SUBJECT_HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn subject_hash() -> ContentHash {
        SUBJECT_HEX.parse().unwrap()
    }

    /// Seed a manifest artifact with a synthetic sha256 derived from
    /// `seed`, plus a content-reference row that points at the path
    /// digest and carries the supplied artifact_type / media_type
    /// metadata. Async because the [`ContentReferenceIndex::insert`]
    /// port returns a future — calling it from a sync helper would
    /// require nesting tokio runtimes (which panics).
    async fn seed_referrer(
        artifacts: &MockArtifactRepository,
        content_references: &MockContentReferenceIndex,
        repo_id: Uuid,
        seed: u8,
        size: i64,
        artifact_type: Option<&str>,
        media_type: Option<&str>,
    ) -> (Uuid, ContentHash) {
        // Build a unique 64-char hex per seed by repeating the byte.
        let hex: String = format!("{seed:02x}").repeat(32);
        let hash: ContentHash = hex.parse().unwrap();

        let mut a = sample_artifact(QuarantineStatus::None);
        a.repository_id = repo_id;
        a.sha256_checksum = hash.clone();
        a.size_bytes = size;
        a.path = format!("manifests/sha256:{hex}");
        let id = a.id;
        artifacts.insert(a);

        let mut metadata = serde_json::Map::new();
        if let Some(at) = artifact_type {
            metadata.insert("artifact_type".into(), serde_json::Value::String(at.into()));
        }
        if let Some(mt) = media_type {
            metadata.insert("media_type".into(), serde_json::Value::String(mt.into()));
        }

        let row = ContentReference {
            source_artifact_id: id,
            target_content_hash: subject_hash(),
            kind: "oci_subject".into(),
            metadata: serde_json::Value::Object(metadata),
            repository_id: repo_id,
            recorded_at: Utc::now(),
        };
        // Insert directly via the port — the production write path is
        // exercised by the manifest_write tests; here we only need the
        // read-side projection to be primed.
        content_references.insert(row).await.unwrap();

        (id, hash)
    }

    // -------------------- Metrics helpers --------------------

    type MetricEntry = (
        CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        DebugValue,
    );

    fn capture<T, F>(f: F) -> (Snapshot, T)
    where
        F: FnOnce() -> T,
    {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let out = metrics::with_local_recorder(&recorder, f);
        (snapshotter.snapshot(), out)
    }

    fn find_counter<'a>(
        entries: &'a [MetricEntry],
        name: &str,
        expected: &[(&str, &str)],
    ) -> Option<&'a DebugValue> {
        entries.iter().find_map(|(ck, _, _, dv)| {
            if ck.kind() != MetricKind::Counter || ck.key().name() != name {
                return None;
            }
            let ok = expected
                .iter()
                .all(|(k, v)| ck.key().labels().any(|l| l.key() == *k && l.value() == *v));
            ok.then_some(dv)
        })
    }

    use hort_domain::ports::content_reference_index::ContentReferenceIndex;

    // -------------------- 1. Empty result → 200 manifests:[] --------------------

    /// THE first TDD test, per the backlog ("regressions slip in as
    /// 404"). An unknown subject returns 200 + the OCI image-index
    /// content-type + an empty manifests array.
    #[test]
    fn empty_result_returns_200_with_empty_manifests_array() {
        let (snapshot, (status, content_type, body)) = capture(|| {
            run(async {
                let h = harness();
                h.repositories.insert(oci_repo("myrepo"));
                let resp = serve(
                    h.ctx,
                    "myrepo",
                    "library/nginx",
                    &format!("sha256:{SUBJECT_HEX}"),
                    None,
                    None,
                )
                .await;
                let status = resp.status();
                let content_type = resp
                    .headers()
                    .get(CONTENT_TYPE)
                    .map(|v| v.to_str().unwrap().to_string());
                let body = axum::body::to_bytes(resp.into_body(), 8 * 1024)
                    .await
                    .unwrap()
                    .to_vec();
                (status, content_type, body)
            })
        });
        assert_eq!(status, StatusCode::OK);
        assert_eq!(content_type.as_deref(), Some(IMAGE_INDEX_MEDIA_TYPE));
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["schemaVersion"], 2);
        assert_eq!(parsed["mediaType"], IMAGE_INDEX_MEDIA_TYPE);
        let manifests = parsed["manifests"]
            .as_array()
            .expect("manifests must be an array, even when empty");
        assert!(
            manifests.is_empty(),
            "empty result must emit `manifests: []`, not 404"
        );

        // Metric: result=success, even on empty list — the call
        // succeeded; emptiness is a property of the data, not the
        // request.
        let entries: Vec<MetricEntry> = snapshot.into_vec();
        let counter = find_counter(
            &entries,
            "hort_content_reference_queries_total",
            &[
                ("format", "oci"),
                ("repository", "myrepo"),
                ("result", "success"),
            ],
        )
        .expect("hort_content_reference_queries_total{result=success} must fire on 200");
        assert_eq!(*counter, DebugValue::Counter(1));
    }

    // -------------------- 2. One referrer (no filter) --------------------

    #[test]
    fn one_referrer_unfiltered_returns_one_manifest_entry() {
        let (status, body) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            let (_id, _hash) = seed_referrer(
                &h.artifacts,
                &h.content_references,
                repo_id,
                0xab,
                512,
                Some("application/vnd.example.signature"),
                Some("application/vnd.oci.image.manifest.v1+json"),
            )
            .await;
            let resp = serve(
                h.ctx,
                "myrepo",
                "library/nginx",
                &format!("sha256:{SUBJECT_HEX}"),
                None,
                None,
            )
            .await;
            let status = resp.status();
            let body = axum::body::to_bytes(resp.into_body(), 16 * 1024)
                .await
                .unwrap()
                .to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::OK);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let manifests = parsed["manifests"].as_array().unwrap();
        assert_eq!(manifests.len(), 1);
        assert_eq!(
            manifests[0]["digest"],
            format!("sha256:{}", "ab".repeat(32))
        );
        assert_eq!(manifests[0]["size"], 512);
        assert_eq!(
            manifests[0]["mediaType"],
            "application/vnd.oci.image.manifest.v1+json"
        );
        assert_eq!(
            manifests[0]["artifactType"],
            "application/vnd.example.signature"
        );
    }

    // -------------------- 3. Two referrers + artifactType filter --------------------

    #[test]
    fn two_referrers_with_artifact_type_filter_returns_only_matching_subset() {
        let (status, body) = run(async {
            let h = harness();
            let repo = oci_repo("myrepo");
            let repo_id = repo.id;
            h.repositories.insert(repo);
            // Referrer A — `application/vnd.spdx+json`. Should match.
            seed_referrer(
                &h.artifacts,
                &h.content_references,
                repo_id,
                0x11,
                100,
                Some("application/vnd.spdx+json"),
                Some("application/vnd.oci.image.manifest.v1+json"),
            )
            .await;
            // Referrer B — `application/vnd.cyclonedx+json`. Should be
            // filtered out.
            seed_referrer(
                &h.artifacts,
                &h.content_references,
                repo_id,
                0x22,
                200,
                Some("application/vnd.cyclonedx+json"),
                Some("application/vnd.oci.image.manifest.v1+json"),
            )
            .await;
            let resp = serve(
                h.ctx,
                "myrepo",
                "library/nginx",
                &format!("sha256:{SUBJECT_HEX}"),
                Some("application/vnd.spdx+json"),
                None,
            )
            .await;
            let status = resp.status();
            let body = axum::body::to_bytes(resp.into_body(), 16 * 1024)
                .await
                .unwrap()
                .to_vec();
            (status, body)
        });
        assert_eq!(status, StatusCode::OK);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let manifests = parsed["manifests"].as_array().unwrap();
        assert_eq!(
            manifests.len(),
            1,
            "filter must keep ONLY the matching subset"
        );
        // The only surviving entry must be the SPDX referrer (digest
        // built from byte 0x11).
        assert_eq!(
            manifests[0]["digest"],
            format!("sha256:{}", "11".repeat(32))
        );
        assert_eq!(manifests[0]["artifactType"], "application/vnd.spdx+json");
    }

    // -------------------- 4. Repo missing → 404 NAME_UNKNOWN --------------------

    #[test]
    fn missing_repo_returns_404_name_unknown_and_increments_not_found_metric() {
        let (snapshot, (status, body)) = capture(|| {
            run(async {
                let h = harness();
                // No repository inserted — find_by_key misses.
                let resp = serve(
                    h.ctx,
                    "missing",
                    "library/nginx",
                    &format!("sha256:{SUBJECT_HEX}"),
                    None,
                    None,
                )
                .await;
                let status = resp.status();
                let body = axum::body::to_bytes(resp.into_body(), 4 * 1024)
                    .await
                    .unwrap()
                    .to_vec();
                (status, body)
            })
        });
        assert_eq!(status, StatusCode::NOT_FOUND);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "NAME_UNKNOWN");

        let entries: Vec<MetricEntry> = snapshot.into_vec();
        // The `repository` label is the `unknown` sentinel — NOT the
        // requested key. The toggle is on by default, but a flood of
        // made-up repo_keys would inflate cardinality without bound,
        // so an unresolved-repo emission collapses to the
        // `REPOSITORY_UNKNOWN` sentinel.
        let counter = find_counter(
            &entries,
            "hort_content_reference_queries_total",
            &[
                ("format", "oci"),
                ("repository", hort_app::metrics::values::REPOSITORY_UNKNOWN),
                ("result", "not_found"),
            ],
        )
        .expect("hort_content_reference_queries_total{result=not_found} must fire on missing repo");
        assert_eq!(*counter, DebugValue::Counter(1));
    }

    // -------------------- 5. Digest malformed → 400 DIGEST_INVALID --------------------

    #[test]
    fn malformed_digest_returns_400_digest_invalid_and_increments_digest_invalid_metric() {
        let (snapshot, (status, body)) = capture(|| {
            run(async {
                let h = harness();
                h.repositories.insert(oci_repo("myrepo"));
                let resp =
                    serve(h.ctx, "myrepo", "library/nginx", "not-a-digest", None, None).await;
                let status = resp.status();
                let body = axum::body::to_bytes(resp.into_body(), 4 * 1024)
                    .await
                    .unwrap()
                    .to_vec();
                (status, body)
            })
        });
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["errors"][0]["code"], "DIGEST_INVALID");

        let entries: Vec<MetricEntry> = snapshot.into_vec();
        let counter = find_counter(
            &entries,
            "hort_content_reference_queries_total",
            &[
                ("format", "oci"),
                ("repository", "myrepo"),
                ("result", "digest_invalid"),
            ],
        )
        .expect(
            "hort_content_reference_queries_total{result=digest_invalid} must fire on bad digest",
        );
        assert_eq!(*counter, DebugValue::Counter(1));
    }

    // -------------------- 6. METRICS_INCLUDE_REPOSITORY_LABEL=false --------------------

    /// Pin the `METRICS_INCLUDE_REPOSITORY_LABEL=false` semantics
    /// claimed by the metrics catalog (`docs/metrics-catalog.md` §
    /// "Content-reference index queries"). With the toggle off, the
    /// counter MUST emit `repository="_all"` regardless of which
    /// `repo_key` the request asked for. A regression that hard-coded
    /// the raw repo_key here would inflate series cardinality on
    /// large deployments — the toggle exists exactly to bound that.
    #[test]
    fn label_toggle_off_collapses_repository_to_all_sentinel() {
        use hort_http_core::test_support::build_mock_ctx_with_label_flag;

        let (snapshot, ()) = capture(|| {
            run(async {
                let handle = PrometheusBuilder::new().build_recorder().handle();
                let (ctx, mocks) = build_mock_ctx_with_label_flag(
                    handle, /* include_repository_label = */ false,
                );
                mocks.repositories.insert(oci_repo("myrepo"));
                let resp = serve(
                    ctx,
                    "myrepo",
                    "library/nginx",
                    &format!("sha256:{SUBJECT_HEX}"),
                    None,
                    None,
                )
                .await;
                // Sanity: the success path should still 200 — the
                // toggle only affects the metric label, not the HTTP
                // shape.
                assert_eq!(resp.status(), StatusCode::OK);
            })
        });
        let entries: Vec<MetricEntry> = snapshot.into_vec();

        // POSITIVE: the `_all` sentinel series exists with the
        // success result.
        let collapsed = find_counter(
            &entries,
            "hort_content_reference_queries_total",
            &[
                ("format", "oci"),
                ("repository", hort_app::metrics::values::REPOSITORY_ALL),
                ("result", "success"),
            ],
        )
        .expect("with METRICS_INCLUDE_REPOSITORY_LABEL=false, repository must collapse to `_all`");
        assert_eq!(*collapsed, DebugValue::Counter(1));

        // NEGATIVE: the raw repo_key MUST NOT appear as a label
        // value. A regression that ignores the toggle would emit
        // `repository="myrepo"` here.
        assert!(
            find_counter(
                &entries,
                "hort_content_reference_queries_total",
                &[("format", "oci"), ("repository", "myrepo")],
            )
            .is_none(),
            "raw repo key must NOT leak into the metric when the toggle is off"
        );
    }
}
